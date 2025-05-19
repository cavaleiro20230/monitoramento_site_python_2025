import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import datetime
import re
import os
import socket
import json
import threading
import time
import queue
import random
from collections import Counter, deque
import csv
import sqlite3
import hashlib

class SistemaMonitoramento(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Sistema de Monitoramento de Logs JBOSS")
        self.geometry("1000x600")
        self.configure(bg="#f0f0f0")
        
        # Variáveis globais
        self.logs_data = None  # DataFrame para exibição (filtrado)
        self.logs_completos = None  # DataFrame completo com todos os logs
        self.usuario_atual = None
        self.caminho_logs = None
        self.max_logs_memoria = 10000  # Limite de logs em memória
        self.monitoramento_ativo = False
        self.thread_monitoramento = None
        self.fila_logs = queue.Queue()  # Fila para comunicação entre threads
        self.alertas = []  # Lista para armazenar alertas
        self.db_path = "logs_cache.db"  # Caminho para o banco de dados SQLite
        
        # Configurações de alertas
        self.alertas_config = {
            "falhas_login": 3,  # Número de falhas de login para gerar alerta
            "acessos_suspeitos": True,  # Alertar sobre acessos fora do horário comercial
            "urls_restritas": ["/admin", "/config", "/system", "/api/admin"]  # URLs restritas
        }
        
        # Inicializar banco de dados
        self.inicializar_db()
        
        # Carregar configurações salvas
        self.carregar_configuracoes()
        
        # Inicializar frames
        self.frames = {}
        
        # Configurar container principal
        container = tk.Frame(self)
        container.pack(fill="both", expand=True)
        
        # Criar frames para cada tela
        for F in (TelaLogin, TelaDashboard, TelaDetalhes, TelaConfiguracoes, TelaRelatorios, TelaURLs, TelaAlertas):
            frame_name = F.__name__
            frame = F(parent=container, controller=self)
            self.frames[frame_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        
        # Iniciar com a tela de login
        self.mostrar_frame("TelaLogin")
        
        # Configurar manipulador de fechamento da janela
        self.protocol("WM_DELETE_WINDOW", self.ao_fechar)
    
    def inicializar_db(self):
        """Inicializa o banco de dados SQLite para cache de logs"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Criar tabela de logs se não existir
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                data TEXT,
                hora TEXT,
                nivel TEXT,
                categoria TEXT,
                servidor TEXT,
                thread TEXT,
                mensagem TEXT,
                usuario TEXT,
                ip TEXT,
                url TEXT,
                operacao TEXT,
                status TEXT,
                timestamp TEXT
            )
            ''')
            
            # Criar tabela de configurações se não existir
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS configuracoes (
                chave TEXT PRIMARY KEY,
                valor TEXT
            )
            ''')
            
            # Criar tabela de alertas se não existir
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS alertas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tipo TEXT,
                nivel TEXT,
                usuario TEXT,
                ip TEXT,
                url TEXT,
                data TEXT,
                hora TEXT,
                mensagem TEXT,
                detalhes TEXT,
                timestamp TEXT,
                lido INTEGER DEFAULT 0
            )
            ''')
            
            # Criar índices para melhorar performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_data ON logs (data)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_usuario ON logs (usuario)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_ip ON logs (ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_url ON logs (url)')
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Erro ao inicializar banco de dados: {str(e)}")
    
    def mostrar_frame(self, frame_name):
        """Mostra o frame especificado"""
        frame = self.frames[frame_name]
        frame.tkraise()
        
        # Atualizar dados se necessário
        if frame_name == "TelaDashboard" and self.usuario_atual:
            self.frames["TelaDashboard"].atualizar_dashboard()
        elif frame_name == "TelaDetalhes" and self.logs_data is not None:
            self.frames["TelaDetalhes"].carregar_logs(self.logs_data)
        elif frame_name == "TelaURLs" and self.logs_data is not None:
            self.frames["TelaURLs"].carregar_dados()
        elif frame_name == "TelaAlertas":
            self.frames["TelaAlertas"].carregar_alertas()
    
    def carregar_dados_logs(self, caminho=None):
        """Carrega dados de logs de um arquivo ou diretório"""
        if not caminho and self.caminho_logs:
            caminho = self.caminho_logs
        
        if not caminho:
            messagebox.showerror("Erro", "Caminho de logs não especificado.")
            return False
        
        try:
            if os.path.isdir(caminho):
                # Carregar logs de um diretório
                return self.carregar_logs_diretorio(caminho)
            else:
                # Carregar logs de um arquivo
                return self.carregar_logs_arquivo(caminho)
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao carregar logs: {str(e)}")
            return False
    
    def carregar_logs_diretorio(self, diretorio):
        """Carrega logs de todos os arquivos .log em um diretório"""
        arquivos_log = [os.path.join(diretorio, f) for f in os.listdir(diretorio) if f.endswith('.log')]
        
        if not arquivos_log:
            messagebox.showwarning("Aviso", f"Nenhum arquivo de log (.log) encontrado no diretório: {diretorio}")
            return False
        
        # Ordenar arquivos por data de modificação (mais recentes primeiro)
        arquivos_log.sort(key=lambda x: os.path.getmtime(x), reverse=True)
        
        # Limitar a quantidade de arquivos para não sobrecarregar a memória
        max_arquivos = 5
        if len(arquivos_log) > max_arquivos:
            arquivos_log = arquivos_log[:max_arquivos]
        
        # Processar cada arquivo
        logs_combinados = []
        for arquivo in arquivos_log:
            try:
                logs = self.processar_arquivo_log(arquivo)
                if logs:
                    logs_combinados.extend(logs)
            except Exception as e:
                print(f"Erro ao processar arquivo {arquivo}: {str(e)}")
        
        if not logs_combinados:
            messagebox.showwarning("Aviso", "Nenhum log válido encontrado nos arquivos.")
            return False
        
        # Converter para DataFrame
        self.logs_completos = pd.DataFrame(logs_combinados)
        
        # Limitar quantidade de logs em memória
        if len(self.logs_completos) > self.max_logs_memoria:
            self.logs_completos = self.logs_completos.head(self.max_logs_memoria)
        
        # Ordenar por data e hora
        self.logs_completos = self.logs_completos.sort_values(by=["data", "hora"], ascending=False)
        
        # Copiar para logs_data (para exibição)
        self.logs_data = self.logs_completos.copy()
        
        # Salvar logs no banco de dados para cache
        self.salvar_logs_db(logs_combinados)
        
        return True
    
    def carregar_logs_arquivo(self, arquivo):
        """Carrega logs de um único arquivo"""
        try:
            logs = self.processar_arquivo_log(arquivo)
            
            if not logs:
                messagebox.showwarning("Aviso", "Nenhum log válido encontrado no arquivo.")
                return False
            
            # Converter para DataFrame
            self.logs_completos = pd.DataFrame(logs)
            
            # Limitar quantidade de logs em memória
            if len(self.logs_completos) > self.max_logs_memoria:
                self.logs_completos = self.logs_completos.head(self.max_logs_memoria)
            
            # Ordenar por data e hora
            self.logs_completos = self.logs_completos.sort_values(by=["data", "hora"], ascending=False)
            
            # Copiar para logs_data (para exibição)
            self.logs_data = self.logs_completos.copy()
            
            # Salvar logs no banco de dados para cache
            self.salvar_logs_db(logs)
            
            return True
        
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao carregar arquivo de log: {str(e)}")
            return False
    
    def salvar_logs_db(self, logs):
        """Salva logs no banco de dados SQLite para cache"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Preparar dados para inserção
            for log in logs:
                # Adicionar timestamp atual
                log['timestamp'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                
                # Inserir no banco de dados
                cursor.execute('''
                INSERT INTO logs (data, hora, nivel, categoria, servidor, thread, mensagem, usuario, ip, url, operacao, status, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    log.get('data', ''),
                    log.get('hora', ''),
                    log.get('nivel', ''),
                    log.get('categoria', ''),
                    log.get('servidor', ''),
                    log.get('thread', ''),
                    log.get('mensagem', ''),
                    log.get('usuario', ''),
                    log.get('ip', ''),
                    log.get('url', ''),
                    log.get('operacao', ''),
                    log.get('status', ''),
                    log.get('timestamp', '')
                ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Erro ao salvar logs no banco de dados: {str(e)}")
    
    def carregar_logs_db(self, filtros=None, limite=1000):
        """Carrega logs do banco de dados SQLite com filtros opcionais"""
        try:
            conn = sqlite3.connect(self.db_path)
            
            # Construir consulta SQL com filtros
            query = "SELECT * FROM logs"
            params = []
            
            if filtros:
                where_clauses = []
                
                if 'data' in filtros and filtros['data']:
                    where_clauses.append("data = ?")
                    params.append(filtros['data'])
                
                if 'usuario' in filtros and filtros['usuario']:
                    where_clauses.append("usuario LIKE ?")
                    params.append(f"%{filtros['usuario']}%")
                
                if 'ip' in filtros and filtros['ip']:
                    where_clauses.append("ip LIKE ?")
                    params.append(f"%{filtros['ip']}%")
                
                if 'url' in filtros and filtros['url']:
                    where_clauses.append("url LIKE ?")
                    params.append(f"%{filtros['url']}%")
                
                if 'nivel' in filtros and filtros['nivel'] and filtros['nivel'] != "TODOS":
                    where_clauses.append("nivel = ?")
                    params.append(filtros['nivel'])
                
                if 'status' in filtros and filtros['status'] and filtros['status'] != "TODOS":
                    where_clauses.append("status = ?")
                    params.append(filtros['status'])
                
                if where_clauses:
                    query += " WHERE " + " AND ".join(where_clauses)
            
            # Adicionar ordenação e limite
            query += " ORDER BY data DESC, hora DESC LIMIT ?"
            params.append(limite)
            
            # Executar consulta
            df = pd.read_sql_query(query, conn, params=params)
            conn.close()
            
            if df.empty:
                return None
            
            return df
        
        except Exception as e:
            print(f"Erro ao carregar logs do banco de dados: {str(e)}")
            return None
    
    def processar_arquivo_log(self, arquivo):
        """Processa um arquivo de log do JBOSS e extrai informações relevantes"""
        logs = []
        
        try:
            with open(arquivo, 'r', encoding='utf-8', errors='ignore') as f:
                linhas = f.readlines()
            
            # Padrões de regex para diferentes formatos de log
            # Formato 1: [data] [hora] [nível] [categoria] [mensagem]
            padrao1 = r'\[(.*?)\]\s+\[(.*?)\]\s+\[(.*?)\]\s+\[(.*?)\]\s+(.*)'
            
            # Formato 2: data hora [servidor] [nível] [categoria] - mensagem
            padrao2 = r'(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2},\d{3})\s+\[(.*?)\]\s+\[(.*?)\]\s+\[(.*?)\]\s+-\s+(.*)'
            
            # Formato 3: data hora INFO [categoria] (thread) mensagem
            padrao3 = r'(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2},\d{3})\s+(\w+)\s+\[(.*?)\]\s+$$(.*?)$$\s+(.*)'
            
            for linha in linhas:
                linha = linha.strip()
                if not linha:
                    continue
                
                # Tentar diferentes padrões
                match = re.match(padrao1, linha) or re.match(padrao2, linha) or re.match(padrao3, linha)
                
                if match:
                    # Extrair informações com base no padrão que deu match
                    if match.re.pattern == padrao1:
                        data, hora, nivel, categoria, mensagem = match.groups()
                        servidor = "desconhecido"
                        thread = "desconhecido"
                    elif match.re.pattern == padrao2:
                        data, hora, servidor, nivel, categoria, mensagem = match.groups()
                        thread = "desconhecido"
                    else:  # padrao3
                        data, hora, nivel, categoria, thread, mensagem = match.groups()
                        servidor = "desconhecido"
                    
                    # Processar a mensagem para extrair informações adicionais
                    log_info = self.extrair_info_mensagem(mensagem)
                    
                    # Adicionar informações básicas
                    log_info.update({
                        "data": self.formatar_data(data),
                        "hora": self.formatar_hora(hora),
                        "nivel": nivel,
                        "categoria": categoria,
                        "servidor": servidor,
                        "thread": thread,
                        "mensagem": mensagem
                    })
                    
                    logs.append(log_info)
                else:
                    # Tentar extrair informações básicas da linha
                    log_info = self.extrair_info_linha_simples(linha)
                    if log_info:
                        logs.append(log_info)
            
            # Se não encontrou logs no formato esperado, gerar dados de exemplo
            if not logs:
                print(f"Nenhum log encontrado no formato esperado em {arquivo}. Gerando dados de exemplo.")
                self.gerar_dados_exemplo()
                return []
            
            return logs
        
        except Exception as e:
            print(f"Erro ao processar arquivo {arquivo}: {str(e)}")
            # Em caso de erro, gerar dados de exemplo
            self.gerar_dados_exemplo()
            return []
    
    def extrair_info_mensagem(self, mensagem):
        """Extrai informações adicionais da mensagem de log"""
        info = {
            "usuario": "desconhecido",
            "ip": "desconhecido",
            "url": "desconhecido",
            "operacao": "desconhecido",
            "status": "desconhecido"
        }
        
        # Extrair usuário
        padrao_usuario = r'user[=:][\s]*[\'"]?([\w\.@-]+)[\'"]?'
        match_usuario = re.search(padrao_usuario, mensagem, re.IGNORECASE)
        if match_usuario:
            info["usuario"] = match_usuario.group(1)
        
        # Extrair IP
        padrao_ip = r'(?:IP|address|from)[=:][\s]*[\'"]?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[\'"]?'
        match_ip = re.search(padrao_ip, mensagem, re.IGNORECASE)
        if match_ip:
            info["ip"] = match_ip.group(1)
        
        # Extrair URL
        padrao_url = r'(?:URL|uri|path)[=:][\s]*[\'"]?((?:/[\w\.-]+)+)[\'"]?'
        match_url = re.search(padrao_url, mensagem, re.IGNORECASE)
        if match_url:
            info["url"] = match_url.group(1)
        
        # Determinar operação
        if re.search(r'login|authenticate|auth', mensagem, re.IGNORECASE):
            info["operacao"] = "LOGIN"
        elif re.search(r'logout|signout', mensagem, re.IGNORECASE):
            info["operacao"] = "LOGOUT"
        elif re.search(r'GET|view|read|select', mensagem, re.IGNORECASE):
            info["operacao"] = "VIEW"
        elif re.search(r'POST|PUT|update|modify', mensagem, re.IGNORECASE):
            info["operacao"] = "UPDATE"
        elif re.search(r'DELETE|remove', mensagem, re.IGNORECASE):
            info["operacao"] = "DELETE"
        
        # Determinar status
        if re.search(r'success|successful|succeeded|ok|200', mensagem, re.IGNORECASE):
            info["status"] = "SUCCESS"
        elif re.search(r'fail|failed|error|exception|denied|401|403|404|500', mensagem, re.IGNORECASE):
            info["status"] = "FAILED"
        
        return info
    
    def extrair_info_linha_simples(self, linha):
        """Tenta extrair informações básicas de uma linha de log simples"""
        # Tentar extrair data e hora
        padrao_data_hora = r'(\d{4}-\d{2}-\d{2}).*?(\d{2}:\d{2}:\d{2})'
        match_data_hora = re.search(padrao_data_hora, linha)
        
        if not match_data_hora:
            return None
        
        data, hora = match_data_hora.groups()
        
        # Informações básicas
        info = {
            "data": self.formatar_data(data),
            "hora": self.formatar_hora(hora),
            "nivel": "INFO" if "INFO" in linha else "ERROR" if "ERROR" in linha else "WARN" if "WARN" in linha else "DEBUG" if "DEBUG" in linha else "UNKNOWN",
            "categoria": "desconhecido",
            "servidor": "desconhecido",
            "thread": "desconhecido",
            "mensagem": linha,
            "usuario": "desconhecido",
            "ip": "desconhecido",
            "url": "desconhecido",
            "operacao": "desconhecido",
            "status": "SUCCESS" if "success" in linha.lower() else "FAILED" if "fail" in linha.lower() or "error" in linha.lower() else "UNKNOWN"
        }
        
        # Tentar extrair IP
        padrao_ip = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
        match_ip = re.search(padrao_ip, linha)
        if match_ip:
            info["ip"] = match_ip.group(1)
        
        # Tentar extrair URL
        padrao_url = r'(?:/[\w\.-]+){2,}'
        match_url = re.search(padrao_url, linha)
        if match_url:
            info["url"] = match_url.group(0)
        
        return info
    
    def formatar_data(self, data):
        """Formata a data para o formato padrão YYYY-MM-DD"""
        try:
            # Tentar diferentes formatos de data
            formatos = [
                '%Y-%m-%d',  # 2023-01-31
                '%d/%m/%Y',  # 31/01/2023
                '%d-%m-%Y',  # 31-01-2023
                '%d.%m.%Y',  # 31.01.2023
                '%b %d, %Y',  # Jan 31, 2023
                '%d %b %Y',   # 31 Jan 2023
            ]
            
            for formato in formatos:
                try:
                    return datetime.datetime.strptime(data, formato).strftime('%Y-%m-%d')
                except ValueError:
                    continue
            
            # Se nenhum formato funcionar, retornar a data original
            return data
        except:
            # Em caso de erro, retornar a data atual
            return datetime.datetime.now().strftime('%Y-%m-%d')
    
    def formatar_hora(self, hora):
        """Formata a hora para o formato padrão HH:MM:SS"""
        try:
            # Remover milissegundos se presentes
            hora = hora.split(',')[0]
            
            # Tentar diferentes formatos de hora
            formatos = [
                '%H:%M:%S',  # 14:30:45
                '%I:%M:%S %p',  # 02:30:45 PM
                '%H:%M',  # 14:30
                '%I:%M %p',  # 02:30 PM
            ]
            
            for formato in formatos:
                try:
                    return datetime.datetime.strptime(hora, formato).strftime('%H:%M:%S')
                except ValueError:
                    continue
            
            # Se nenhum formato funcionar, retornar a hora original
            return hora
        except:
            # Em caso de erro, retornar a hora atual
            return datetime.datetime.now().strftime('%H:%M:%S')
    
    def gerar_dados_exemplo(self):
        """Gera dados de exemplo para demonstração"""
        # Lista de usuários de exemplo
        usuarios = ["admin", "joao.silva", "maria.santos", "carlos.oliveira", "ana.pereira"]
        
        # Lista de IPs de exemplo
        ips = ["192.168.1." + str(i) for i in range(1, 20)] + ["10.0.0." + str(i) for i in range(1, 10)]
        
        # Lista de URLs/endpoints de exemplo
        urls = [
            "/app/dashboard",
            "/app/users",
            "/app/reports",
            "/app/settings",
            "/api/data",
            "/api/users",
            "/api/auth/login",
            "/api/auth/logout",
            "/app/products",
            "/app/orders"
        ]
        
        # Lista de níveis de log
        niveis = ["INFO", "WARN", "ERROR", "DEBUG"]
        
        # Lista de categorias
        categorias = ["Security", "Authentication", "Database", "Application", "System"]
        
        # Lista de servidores
        servidores = ["jboss1", "jboss2", "jboss3"]
        
        # Gerar 100 registros de log
        data_atual = datetime.datetime.now()
        logs = []
        
        for i in range(100):
            # Data aleatória nos últimos 7 dias
            delta = datetime.timedelta(
                days=random.randint(0, 7),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59),
                seconds=random.randint(0, 59)
            )
            data_log = data_atual - delta
            
            # Selecionar valores aleatórios
            usuario = random.choice(usuarios)
            ip = random.choice(ips)
            url = random.choice(urls)
            nivel = random.choice(niveis)
            categoria = random.choice(categorias)
            servidor = random.choice(servidores)
            thread = f"Thread-{random.randint(1, 100)}"
            
            # Tipo de operação
            operacao = random.choice(["LOGIN", "LOGOUT", "VIEW", "UPDATE", "DELETE"])
            
            # Status
            status = random.choice(["SUCCESS", "FAILED", "SUCCESS", "SUCCESS", "SUCCESS"])
            
            # Gerar mensagem
            if operacao == "LOGIN":
                if status == "SUCCESS":
                    mensagem = f"User {usuario} successfully logged in from IP={ip}"
                else:
                    mensagem = f"Failed login attempt for user {usuario} from IP={ip}"
            elif operacao == "LOGOUT":
                mensagem = f"User {usuario} logged out"
            elif operacao == "VIEW":
                mensagem = f"User {usuario} accessed URL={url} from IP={ip}"
            elif operacao == "UPDATE":
                mensagem = f"User {usuario} updated data at URL={url} from IP={ip}"
            elif operacao == "DELETE":
                mensagem = f"User {usuario} deleted data at URL={url} from IP={ip}"
            
            logs.append({
                "data": data_log.strftime("%Y-%m-%d"),
                "hora": data_log.strftime("%H:%M:%S"),
                "nivel": nivel,
                "categoria": categoria,
                "servidor": servidor,
                "thread": thread,
                "mensagem": mensagem,
                "usuario": usuario,
                "ip": ip,
                "url": url,
                "operacao": operacao,
                "status": status
            })
        
        # Converter para DataFrame
        self.logs_completos = pd.DataFrame(logs)
        
        # Ordenar por data e hora
        self.logs_completos = self.logs_completos.sort_values(by=["data", "hora"], ascending=False)
        
        # Copiar para logs_data (para exibição)
        self.logs_data = self.logs_completos.copy()
        
        # Salvar logs no banco de dados para cache
        self.salvar_logs_db(logs)
    
    def iniciar_monitoramento(self):
        """Inicia o monitoramento em tempo real dos logs"""
        if self.monitoramento_ativo:
            return
        
        self.monitoramento_ativo = True
        
        # Iniciar thread de monitoramento
        self.thread_monitoramento = threading.Thread(target=self.monitorar_logs, daemon=True)
        self.thread_monitoramento.start()
        
        # Iniciar verificação periódica da fila
        self.after(1000, self.verificar_fila_logs)
    
    def parar_monitoramento(self):
        """Para o monitoramento em tempo real dos logs"""
        self.monitoramento_ativo = False
        
        # A thread vai parar automaticamente na próxima iteração
        if self.thread_monitoramento:
            self.thread_monitoramento.join(timeout=1.0)
            self.thread_monitoramento = None
    
    def monitorar_logs(self):
        """Função executada em uma thread separada para monitorar logs"""
        ultimo_tamanho = {}  # Dicionário para armazenar o último tamanho de cada arquivo
        
        while self.monitoramento_ativo:
            try:
                if not self.caminho_logs:
                    time.sleep(2)
                    continue
                
                if os.path.isdir(self.caminho_logs):
                    # Monitorar todos os arquivos .log no diretório
                    arquivos_log = [os.path.join(self.caminho_logs, f) for f in os.listdir(self.caminho_logs) if f.endswith('.log')]
                    
                    for arquivo in arquivos_log:
                        self.verificar_novos_logs(arquivo, ultimo_tamanho)
                else:
                    # Monitorar um único arquivo
                    self.verificar_novos_logs(self.caminho_logs, ultimo_tamanho)
                
                # Aguardar antes da próxima verificação
                time.sleep(2)
            
            except Exception as e:
                print(f"Erro no monitoramento: {str(e)}")
                time.sleep(5)  # Aguardar mais tempo em caso de erro
    
    def verificar_novos_logs(self, arquivo, ultimo_tamanho):
        """Verifica se há novos logs em um arquivo"""
        try:
            # Verificar se o arquivo existe
            if not os.path.exists(arquivo):
                return
            
            # Obter o tamanho atual do arquivo
            tamanho_atual = os.path.getsize(arquivo)
            
            # Se é a primeira vez que verificamos este arquivo, apenas armazenar o tamanho
            if arquivo not in ultimo_tamanho:
                ultimo_tamanho[arquivo] = tamanho_atual
                return
            
            # Se o arquivo não mudou de tamanho, não há novos logs
            if tamanho_atual <= ultimo_tamanho[arquivo]:
                return
            
            # Ler apenas as novas linhas
            with open(arquivo, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(ultimo_tamanho[arquivo])
                novas_linhas = f.readlines()
            
            # Atualizar o último tamanho conhecido
            ultimo_tamanho[arquivo] = tamanho_atual
            
            # Processar as novas linhas
            for linha in novas_linhas:
                linha = linha.strip()
                if not linha:
                    continue
                
                # Tentar extrair informações da linha
                log_info = self.extrair_info_linha_simples(linha)
                
                if log_info:
                    # Adicionar à fila para processamento na thread principal
                    self.fila_logs.put(log_info)
        
        except Exception as e:
            print(f"Erro ao verificar novos logs em {arquivo}: {str(e)}")
    
    def verificar_fila_logs(self):
        """Verifica a fila de logs e atualiza a interface"""
        # Processar até 100 logs por vez para não bloquear a interface
        logs_processados = 0
        novos_logs = []
        
        while not self.fila_logs.empty() and logs_processados < 100:
            try:
                log_info = self.fila_logs.get_nowait()
                novos_logs.append(log_info)
                logs_processados += 1
            except queue.Empty:
                break
        
        if novos_logs:
            # Adicionar novos logs ao DataFrame
            novos_df = pd.DataFrame(novos_logs)
            
            if self.logs_completos is None:
                self.logs_completos = novos_df
            else:
                self.logs_completos = pd.concat([novos_df, self.logs_completos], ignore_index=True)
            
            # Limitar quantidade de logs em memória
            if len(self.logs_completos) > self.max_logs_memoria:
                self.logs_completos = self.logs_completos.head(self.max_logs_memoria)
            
            # Ordenar por data e hora
            self.logs_completos = self.logs_completos.sort_values(by=["data", "hora"], ascending=False)
            
            # Atualizar logs_data (para exibição)
            self.logs_data = self.logs_completos.copy()
            
            # Salvar logs no banco de dados para cache
            self.salvar_logs_db(novos_logs)
            
            # Verificar alertas
            for log in novos_logs:
                self.verificar_alerta(log)
            
            # Atualizar interface se estiver na tela relevante
            frame_atual = [f for f in self.frames.values() if f.winfo_viewable()][0]
            frame_name = frame_atual.__class__.__name__
            
            if frame_name == "TelaDashboard":
                self.frames["TelaDashboard"].atualizar_dashboard()
            elif frame_name == "TelaDetalhes":
                self.frames["TelaDetalhes"].carregar_logs(self.logs_data)
            elif frame_name == "TelaURLs":
                self.frames["TelaURLs"].carregar_dados()
        
        # Agendar próxima verificação se o monitoramento estiver ativo
        if self.monitoramento_ativo:
            self.after(1000, self.verificar_fila_logs)
    
    def verificar_alerta(self, log):
        """Verifica se um log deve gerar um alerta"""
        # Verificar falhas de login
        if (log['operacao'] == 'LOGIN' and log['status'] == 'FAILED' and 
            'falhas_login' in self.alertas_config):
            
            # Contar falhas recentes para este usuário/IP
            if self.logs_completos is not None:
                usuario = log['usuario']
                ip = log['ip']
                
                # Filtrar logs recentes (últimas 24 horas)
                data_limite = (datetime.datetime.now() - datetime.timedelta(hours=24)).strftime('%Y-%m-%d')
                logs_recentes = self.logs_completos[
                    (self.logs_completos['data'] >= data_limite) & 
                    (self.logs_completos['operacao'] == 'LOGIN') & 
                    (self.logs_completos['status'] == 'FAILED') & 
                    (self.logs_completos['usuario'] == usuario) & 
                    (self.logs_completos['ip'] == ip)
                ]
                
                # Se o número de falhas atingiu o limite, gerar alerta
                if len(logs_recentes) >= self.alertas_config['falhas_login']:
                    self.adicionar_alerta({
                        'tipo': 'falha_login',
                        'nivel': 'alto',
                        'usuario': usuario,
                        'ip': ip,
                        'url': '',
                        'data': log['data'],
                        'hora': log['hora'],
                        'mensagem': f"Múltiplas falhas de login ({len(logs_recentes)}) para o usuário {usuario} do IP {ip}",
                        'detalhes': f"Detectadas {len(logs_recentes)} tentativas de login malsucedidas nas últimas 24 horas."
                    })
        
        # Verificar acessos fora do horário comercial
        if (self.alertas_config.get('acessos_suspeitos', False) and 
            log['status'] == 'SUCCESS'):
            
            # Extrair hora
            try:
                hora = int(log['hora'].split(':')[0])
                
                # Verificar se está fora do horário comercial (antes das 8h ou depois das 18h)
                if hora < 8 or hora > 18:
                    self.adicionar_alerta({
                        'tipo': 'horario_suspeito',
                        'nivel': 'médio',
                        'usuario': log['usuario'],
                        'ip': log['ip'],
                        'url': log['url'],
                        'data': log['data'],
                        'hora': log['hora'],
                        'mensagem': f"Acesso fora do horário comercial pelo usuário {log['usuario']} às {log['hora']}",
                        'detalhes': f"O usuário {log['usuario']} acessou o sistema do IP {log['ip']} às {log['hora']}, fora do horário comercial (8h-18h)."
                    })
            except:
                pass
        
        # Verificar acessos a URLs restritas
        if ('urls_restritas' in self.alertas_config and 
            self.alertas_config['urls_restritas'] and 
            log['url'] != 'desconhecido'):
            
            for url_restrita in self.alertas_config['urls_restritas']:
                if url_restrita in log['url']:
                    self.adicionar_alerta({
                        'tipo': 'url_restrita',
                        'nivel': 'alto' if log['status'] == 'SUCCESS' else 'médio',
                        'usuario': log['usuario'],
                        'ip': log['ip'],
                        'url': log['url'],
                        'data': log['data'],
                        'hora': log['hora'],
                        'mensagem': f"Acesso a URL restrita {log['url']} pelo usuário {log['usuario']}",
                        'detalhes': f"O usuário {log['usuario']} acessou a URL restrita {log['url']} do IP {log['ip']} às {log['hora']}. Status: {log['status']}"
                    })
                    break
    
    def adicionar_alerta(self, alerta):
        """Adiciona um novo alerta à lista de alertas"""
        # Verificar se já existe um alerta similar recente
        for a in self.alertas:
            if (a['tipo'] == alerta['tipo'] and 
                a['usuario'] == alerta['usuario'] and 
                a['data'] == alerta['data']):
                # Já existe um alerta similar hoje, não duplicar
                return
        
        # Adicionar timestamp
        alerta['timestamp'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Adicionar à lista de alertas
        self.alertas.append(alerta)
        
        # Limitar número de alertas armazenados
        max_alertas = 100
        if len(self.alertas) > max_alertas:
            self.alertas = self.alertas[-max_alertas:]
        
        # Salvar alerta no banco de dados
        self.salvar_alerta_db(alerta)
        
        # Notificar usuário se estiver na tela de alertas
        frame_atual = [f for f in self.frames.values() if f.winfo_viewable()][0]
        frame_name = frame_atual.__class__.__name__
        
        if frame_name == "TelaAlertas":
            self.frames["TelaAlertas"].carregar_alertas()
        else:
            # Mostrar notificação
            self.mostrar_notificacao_alerta(alerta)
    
    def salvar_alerta_db(self, alerta):
        """Salva um alerta no banco de dados"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
            INSERT INTO alertas (tipo, nivel, usuario, ip, url, data, hora, mensagem, detalhes, timestamp, lido)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alerta.get('tipo', ''),
                alerta.get('nivel', ''),
                alerta.get('usuario', ''),
                alerta.get('ip', ''),
                alerta.get('url', ''),
                alerta.get('data', ''),
                alerta.get('hora', ''),
                alerta.get('mensagem', ''),
                alerta.get('detalhes', ''),
                alerta.get('timestamp', ''),
                0  # Não lido
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Erro ao salvar alerta no banco de dados: {str(e)}")
    
    def carregar_alertas_db(self):
        """Carrega alertas do banco de dados"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT tipo, nivel, usuario, ip, url, data, hora, mensagem, detalhes, timestamp, lido, id
            FROM alertas
            ORDER BY timestamp DESC
            ''')
            
            alertas = []
            for row in cursor.fetchall():
                alertas.append({
                    'tipo': row[0],
                    'nivel': row[1],
                    'usuario': row[2],
                    'ip': row[3],
                    'url': row[4],
                    'data': row[5],
                    'hora': row[6],
                    'mensagem': row[7],
                    'detalhes': row[8],
                    'timestamp': row[9],
                    'lido': bool(row[10]),
                    'id': row[11]
                })
            
            conn.close()
            return alertas
        except Exception as e:
            print(f"Erro ao carregar alertas do banco de dados: {str(e)}")
            return []
    
    def marcar_alerta_como_lido(self, alerta_id):
        """Marca um alerta como lido no banco de dados"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('UPDATE alertas SET lido = 1 WHERE id = ?', (alerta_id,))
            
            conn.commit()
            conn.close()
            
            # Atualizar também na lista em memória
            for alerta in self.alertas:
                if alerta.get('id') == alerta_id:
                    alerta['lido'] = True
                    break
        except Exception as e:
            print(f"Erro ao marcar alerta como lido: {str(e)}")
    
    def mostrar_notificacao_alerta(self, alerta):
        """Mostra uma notificação de alerta"""
        # Criar janela de notificação
        notificacao = tk.Toplevel(self)
        notificacao.title("Alerta de Segurança")
        notificacao.geometry("400x150")
        notificacao.configure(bg="#ffebee")  # Fundo vermelho claro
        
        # Ícone de alerta
        frame_icone = tk.Frame(notificacao, bg="#ffebee")
        frame_icone.pack(side="left", padx=10)
        
        # Usar um caractere unicode como ícone
        tk.Label(frame_icone, text="⚠️", font=("Arial", 36), bg="#ffebee").pack()
        
        # Conteúdo do alerta
        frame_conteudo = tk.Frame(notificacao, bg="#ffebee")
        frame_conteudo.pack(side="right", fill="both", expand=True, padx=10, pady=10)
        
        # Título do alerta
        tk.Label(frame_conteudo, text=alerta['mensagem'], 
                font=("Arial", 12, "bold"), bg="#ffebee", wraplength=300, justify="left").pack(anchor="w")
        
        # Detalhes do alerta
        tk.Label(frame_conteudo, text=f"Nível: {alerta['nivel'].upper()}", 
                bg="#ffebee").pack(anchor="w", pady=(10, 0))
        
        tk.Label(frame_conteudo, text=f"Data/Hora: {alerta['data']} {alerta['hora']}", 
                bg="#ffebee").pack(anchor="w")
        
        # Botões
        frame_botoes = tk.Frame(frame_conteudo, bg="#ffebee")
        frame_botoes.pack(fill="x", pady=10)
        
        # Botão para ver todos os alertas
        botao_ver = tk.Button(frame_botoes, text="Ver Alertas", 
                             command=lambda: self.mostrar_frame("TelaAlertas"),
                             bg="#f44336", fg="white")
        botao_ver.pack(side="left", padx=5)
        
        # Botão para fechar
        botao_fechar = tk.Button(frame_botoes, text="Fechar", 
                                command=notificacao.destroy,
                                bg="#9e9e9e", fg="white")
        botao_fechar.pack(side="right", padx=5)
        
        # Auto-fechar após 10 segundos
        notificacao.after(10000, notificacao.destroy)
    
    def carregar_configuracoes(self):
        """Carrega configurações salvas"""
        try:
            # Primeiro tentar carregar do banco de dados
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Verificar se a tabela existe
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='configuracoes'")
            if cursor.fetchone():
                # Carregar configurações
                cursor.execute("SELECT chave, valor FROM configuracoes")
                for chave, valor in cursor.fetchall():
                    if chave == 'caminho_logs':
                        self.caminho_logs = valor
                    elif chave == 'max_logs_memoria':
                        self.max_logs_memoria = int(valor)
                    elif chave == 'alertas_config':
                        self.alertas_config = json.loads(valor)
            
            conn.close()
            
            # Se não encontrou no banco de dados, tentar arquivo JSON
            if not self.caminho_logs and os.path.exists('config.json'):
                with open('config.json', 'r') as f:
                    config = json.load(f)
                
                # Carregar configurações
                if 'caminho_logs' in config:
                    self.caminho_logs = config['caminho_logs']
                
                if 'max_logs_memoria' in config:
                    self.max_logs_memoria = config['max_logs_memoria']
                
                if 'alertas_config' in config:
                    self.alertas_config = config['alertas_config']
                
                # Salvar no banco de dados para futuras execuções
                self.salvar_configuracoes()
        except Exception as e:
            print(f"Erro ao carregar configurações: {str(e)}")
    
    def salvar_configuracoes(self):
        """Salva configurações atuais"""
        try:
            # Salvar no banco de dados
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Limpar configurações existentes
            cursor.execute("DELETE FROM configuracoes")
            
            # Inserir novas configurações
            cursor.execute("INSERT INTO configuracoes (chave, valor) VALUES (?, ?)", 
                          ('caminho_logs', self.caminho_logs or ''))
            
            cursor.execute("INSERT INTO configuracoes (chave, valor) VALUES (?, ?)", 
                          ('max_logs_memoria', str(self.max_logs_memoria)))
            
            cursor.execute("INSERT INTO configuracoes (chave, valor) VALUES (?, ?)", 
                          ('alertas_config', json.dumps(self.alertas_config)))
            
            conn.commit()
            conn.close()
            
            # Também salvar em arquivo JSON para compatibilidade
            config = {
                'caminho_logs': self.caminho_logs,
                'max_logs_memoria': self.max_logs_memoria,
                'alertas_config': self.alertas_config
            }
            
            with open('config.json', 'w') as f:
                json.dump(config, f, indent=4)
            
            return True
        except Exception as e:
            print(f"Erro ao salvar configurações: {str(e)}")
            return False
    
    def ao_fechar(self):
        """Manipulador para quando a janela é fechada"""
        # Parar monitoramento se estiver ativo
        if self.monitoramento_ativo:
            self.parar_monitoramento()
        
        # Salvar configurações
        self.salvar_configuracoes()
        
        # Fechar a aplicação
        self.destroy()

class TelaLogin(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg="#f0f0f0")
        self.controller = controller
        
        # Frame central
        frame_login = tk.Frame(self, bg="#ffffff", padx=20, pady=20)
        frame_login.place(relx=0.5, rely=0.5, anchor="center", width=400, height=350)
        
        # Título
        titulo = tk.Label(frame_login, text="Sistema de Monitoramento", font=("Arial", 16, "bold"), bg="#ffffff")
        titulo.pack(pady=10)
        
        # Subtítulo
        subtitulo = tk.Label(frame_login, text="Logs de Acesso JBOSS", font=("Arial", 12), bg="#ffffff")
        subtitulo.pack(pady=5)
        
        # Campos de login
        tk.Label(frame_login, text="Usuário:", bg="#ffffff").pack(anchor="w", pady=(20, 5))
        self.entrada_usuario = tk.Entry(frame_login, width=30)
        self.entrada_usuario.pack(fill="x", pady=5)
        
        tk.Label(frame_login, text="Senha:", bg="#ffffff").pack(anchor="w", pady=(10, 5))
        self.entrada_senha = tk.Entry(frame_login, width=30, show="*")
        self.entrada_senha.pack(fill="x", pady=5)
        
        # Opção de lembrar usuário
        self.var_lembrar = tk.BooleanVar(value=False)
        tk.Checkbutton(frame_login, text="Lembrar usuário", variable=self.var_lembrar, 
                      bg="#ffffff").pack(anchor="w", pady=5)
        
        # Botão de login
        botao_login = tk.Button(frame_login, text="Entrar", command=self.verificar_login, 
                               bg="#4CAF50", fg="white", width=15, height=2)
        botao_login.pack(pady=10)
        
        # Versão do sistema
        versao = tk.Label(frame_login, text="Versão 1.0.0", font=("Arial", 8), bg="#ffffff", fg="#999999")
        versao.pack(pady=10)
        
        # Carregar usuário salvo, se existir
        self.carregar_usuario_salvo()
    
    def carregar_usuario_salvo(self):
        """Carrega o usuário salvo, se existir"""
        try:
            if os.path.exists('usuario_salvo.json'):
                with open('usuario_salvo.json', 'r') as f:
                    dados = json.load(f)
                
                if 'usuario' in dados:
                    self.entrada_usuario.insert(0, dados['usuario'])
                    self.var_lembrar.set(True)
        except Exception as e:
            print(f"Erro ao carregar usuário salvo: {str(e)}")
    
    def salvar_usuario(self, usuario):
        """Salva o usuário para login futuro"""
        try:
            with open('usuario_salvo.json', 'w') as f:
                json.dump({'usuario': usuario}, f)
        except Exception as e:
            print(f"Erro ao salvar usuário: {str(e)}")
    
    def verificar_login(self):
        """Verifica as credenciais de login"""
        usuario = self.entrada_usuario.get()
        senha = self.entrada_senha.get()
        
        # Em uma implementação real, você verificaria as credenciais em um banco de dados ou LDAP
        # Para demonstração, qualquer usuário com senha "admin" é aceito
        if senha == "admin" and usuario:
            # Salvar usuário se a opção estiver marcada
            if self.var_lembrar.get():
                self.salvar_usuario(usuario)
            else:
                # Remover arquivo de usuário salvo se existir
                if os.path.exists('usuario_salvo.json'):
                    try:
                        os.remove('usuario_salvo.json')
                    except:
                        pass
            
            self.controller.usuario_atual = usuario
            
            # Carregar dados de logs
            if self.controller.caminho_logs:
                self.controller.carregar_dados_logs()
            else:
                # Se não há caminho configurado, gerar dados de exemplo
                self.controller.gerar_dados_exemplo()
            
            # Iniciar monitoramento em tempo real
            self.controller.iniciar_monitoramento()
            
            # Ir para o dashboard
            self.controller.mostrar_frame("TelaDashboard")
        else:
            messagebox.showerror("Erro de Login", "Usuário ou senha incorretos!")

class TelaDashboard(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg="#f0f0f0")
        self.controller = controller
        
        # Barra superior
        self.criar_barra_superior()
        
        # Área principal dividida em painéis
        self.frame_principal = tk.Frame(self, bg="#f0f0f0")
        self.frame_principal.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Criar painéis do dashboard
        self.criar_paineis()
    
    def criar_barra_superior(self):
        """Cria a barra superior com menu de navegação"""
        barra_superior = tk.Frame(self, bg="#333333", height=50)
        barra_superior.pack(fill="x")
        
        # Título
        titulo = tk.Label(barra_superior, text="Dashboard de Monitoramento", 
                         font=("Arial", 12, "bold"), bg="#333333", fg="white")
        titulo.pack(side="left", padx=20)
        
        # Botões de navegação
        botoes = [
            ("Dashboard", lambda: self.controller.mostrar_frame("TelaDashboard")),
            ("Logs Detalhados", lambda: self.controller.mostrar_frame("TelaDetalhes")),
            ("Análise de URLs", lambda: self.controller.mostrar_frame("TelaURLs")),
            ("Alertas", lambda: self.controller.mostrar_frame("TelaAlertas")),
            ("Relatórios", lambda: self.controller.mostrar_frame("TelaRelatorios")),
            ("Configurações", lambda: self.controller.mostrar_frame("TelaConfiguracoes")),
            ("Sair", self.logout)
        ]
        
        for texto, comando in botoes:
            botao = tk.Button(barra_superior, text=texto, command=comando,
                             bg="#333333", fg="white", bd=0, padx=10,
                             activebackground="#555555", activeforeground="white")
            botao.pack(side="left", padx=5)
        
        # Indicador de monitoramento
        self.label_monitoramento = tk.Label(barra_superior, text="Monitoramento: Ativo", 
                                          bg="#333333", fg="#4CAF50", font=("Arial", 10, "bold"))
        self.label_monitoramento.pack(side="right", padx=20)
        
        # Atualizar status de monitoramento
        self.atualizar_status_monitoramento()
    
    def atualizar_status_monitoramento(self):
        """Atualiza o status de monitoramento na interface"""
        if self.controller.monitoramento_ativo:
            self.label_monitoramento.config(text="Monitoramento: Ativo", fg="#4CAF50")
        else:
            self.label_monitoramento.config(text="Monitoramento: Inativo", fg="#f44336")
        
        # Verificar novamente após 1 segundo
        self.after(1000, self.atualizar_status_monitoramento)
    
    def criar_paineis(self):
        """Cria os painéis do dashboard"""
        # Configurar grid 2x2
        self.frame_principal.columnconfigure(0, weight=1)
        self.frame_principal.columnconfigure(1, weight=1)
        self.frame_principal.rowconfigure(0, weight=1)
        self.frame_principal.rowconfigure(1, weight=1)
        
        # Painel 1: Resumo de acessos
        self.painel_resumo = tk.Frame(self.frame_principal, bg="white", padx=10, pady=10)
        self.painel_resumo.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")
        
        # Painel 2: Gráfico de acessos por usuário
        self.painel_usuarios = tk.Frame(self.frame_principal, bg="white", padx=10, pady=10)
        self.painel_usuarios.grid(row=0, column=1, padx=5, pady=5, sticky="nsew")
        
        # Painel 3: Gráfico de acessos por hora
        self.painel_horas = tk.Frame(self.frame_principal, bg="white", padx=10, pady=10)
        self.painel_horas.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")
        
        # Painel 4: Últimos acessos
        self.painel_ultimos = tk.Frame(self.frame_principal, bg="white", padx=10, pady=10)
        self.painel_ultimos.grid(row=1, column=1, padx=5, pady=5, sticky="nsew")
    
    def atualizar_dashboard(self):
        """Atualiza todos os painéis do dashboard com dados atuais"""
        if self.controller.logs_data is None:
            return
        
        # Limpar painéis existentes
        for widget in self.painel_resumo.winfo_children():
            widget.destroy()
        for widget in self.painel_usuarios.winfo_children():
            widget.destroy()
        for widget in self.painel_horas.winfo_children():
            widget.destroy()
        for widget in self.painel_ultimos.winfo_children():
            widget.destroy()
        
        # Atualizar cada painel
        self.atualizar_painel_resumo()
        self.atualizar_painel_usuarios()
        self.atualizar_painel_horas()
        self.atualizar_painel_ultimos()
    
    def atualizar_painel_resumo(self):
        """Atualiza o painel de resumo"""
        logs = self.controller.logs_data
        
        # Título do painel
        tk.Label(self.painel_resumo, text="Resumo de Acessos", 
                font=("Arial", 12, "bold"), bg="white").pack(anchor="w")
        
        # Estatísticas
        total_acessos = len(logs)
        total_usuarios = logs['usuario'].nunique()
        total_ips = logs['ip'].nunique()
        total_urls = logs['url'].nunique()
        acessos_hoje = len(logs[logs['data'] == datetime.datetime.now().strftime("%Y-%m-%d")])
        
        # Frame para estatísticas
        frame_stats = tk.Frame(self.painel_resumo, bg="white")
        frame_stats.pack(fill="both", expand=True, pady=10)
        
        # Configurar grid para estatísticas
        frame_stats.columnconfigure(0, weight=1)
        frame_stats.columnconfigure(1, weight=1)
        frame_stats.rowconfigure(0, weight=1)
        frame_stats.rowconfigure(1, weight=1)
        frame_stats.rowconfigure(2, weight=1)
        
        # Exibir estatísticas em cards
        self.criar_card_estatistica(frame_stats, "Total de Acessos", total_acessos, 0, 0)
        self.criar_card_estatistica(frame_stats, "Usuários Únicos", total_usuarios, 0, 1)
        self.criar_card_estatistica(frame_stats, "IPs Únicos", total_ips, 1, 0)
        self.criar_card_estatistica(frame_stats, "URLs Únicas", total_urls, 1, 1)
        self.criar_card_estatistica(frame_stats, "Acessos Hoje", acessos_hoje, 2,  total_urls, 1, 1)
        self.criar_card_estatistica(frame_stats, "Acessos Hoje", acessos_hoje, 2, 0, colspan=2)
    
    def criar_card_estatistica(self, parent, titulo, valor, row, col, colspan=1):
        """Cria um card para exibir uma estatística"""
        frame = tk.Frame(parent, bg="#f9f9f9", padx=10, pady=10, bd=1, relief="solid")
        frame.grid(row=row, column=col, padx=5, pady=5, sticky="nsew", columnspan=colspan)
        
        tk.Label(frame, text=titulo, font=("Arial", 10), bg="#f9f9f9").pack(anchor="w")
        tk.Label(frame, text=str(valor), font=("Arial", 16, "bold"), bg="#f9f9f9").pack(anchor="center", pady=5)
    
    def atualizar_painel_usuarios(self):
        """Atualiza o gráfico de acessos por usuário"""
        logs = self.controller.logs_data
        
        # Título do painel
        tk.Label(self.painel_usuarios, text="Acessos por Usuário", 
                font=("Arial", 12, "bold"), bg="white").pack(anchor="w")
        
        # Contar acessos por usuário
        contagem_usuarios = logs['usuario'].value_counts().head(5)
        
        # Criar figura para o gráfico
        fig, ax = plt.subplots(figsize=(4, 3), dpi=100)
        bars = ax.bar(contagem_usuarios.index, contagem_usuarios.values, color='skyblue')
        
        # Adicionar valores nas barras
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                   f'{int(height)}', ha='center', va='bottom')
        
        ax.set_ylabel('Número de Acessos')
        ax.set_title('Top 5 Usuários')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        
        # Incorporar o gráfico no tkinter
        canvas = FigureCanvasTkAgg(fig, master=self.painel_usuarios)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)
    
    def atualizar_painel_horas(self):
        """Atualiza o gráfico de acessos por hora"""
        logs = self.controller.logs_data
        
        # Título do painel
        tk.Label(self.painel_horas, text="Acessos por Hora do Dia", 
                font=("Arial", 12, "bold"), bg="white").pack(anchor="w")
        
        # Extrair hora dos logs
        logs['hora_apenas'] = logs['hora'].apply(lambda x: int(x.split(':')[0]))
        contagem_horas = logs['hora_apenas'].value_counts().sort_index()
        
        # Preencher horas faltantes com zeros
        todas_horas = pd.Series(0, index=range(24))
        contagem_horas = contagem_horas.add(todas_horas, fill_value=0).sort_index()
        
        # Criar figura para o gráfico
        fig, ax = plt.subplots(figsize=(4, 3), dpi=100)
        ax.plot(contagem_horas.index, contagem_horas.values, marker='o', linestyle='-', color='green')
        
        ax.set_xlabel('Hora do Dia')
        ax.set_ylabel('Número de Acessos')
        ax.set_title('Distribuição de Acessos por Hora')
        ax.set_xticks(range(0, 24, 3))
        plt.tight_layout()
        
        # Incorporar o gráfico no tkinter
        canvas = FigureCanvasTkAgg(fig, master=self.painel_horas)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)
    
    def atualizar_painel_ultimos(self):
        """Atualiza a lista dos últimos acessos"""
        logs = self.controller.logs_data
        
        # Título do painel
        tk.Label(self.painel_ultimos, text="Últimos Acessos", 
                font=("Arial", 12, "bold"), bg="white").pack(anchor="w")
        
        # Criar tabela para os últimos 5 acessos
        frame_tabela = tk.Frame(self.painel_ultimos, bg="white")
        frame_tabela.pack(fill="both", expand=True, pady=10)
        
        # Cabeçalhos
        colunas = ["Data", "Hora", "Usuário", "URL", "Status"]
        for i, col in enumerate(colunas):
            tk.Label(frame_tabela, text=col, font=("Arial", 10, "bold"), 
                    bg="#e0e0e0", padx=5, pady=2).grid(row=0, column=i, sticky="ew")
        
        # Últimos 5 registros
        ultimos_logs = logs.head(5)
        for i, (_, log) in enumerate(ultimos_logs.iterrows(), 1):
            bg_color = "#f0f0f0" if i % 2 == 0 else "white"
            
            tk.Label(frame_tabela, text=log['data'], bg=bg_color, padx=5, pady=2).grid(row=i, column=0, sticky="ew")
            tk.Label(frame_tabela, text=log['hora'], bg=bg_color, padx=5, pady=2).grid(row=i, column=1, sticky="ew")
            tk.Label(frame_tabela, text=log['usuario'], bg=bg_color, padx=5, pady=2).grid(row=i, column=2, sticky="ew")
            tk.Label(frame_tabela, text=log['url'], bg=bg_color, padx=5, pady=2).grid(row=i, column=3, sticky="ew")
            
            status_color = "green" if log['status'] == "SUCCESS" else "red"
            tk.Label(frame_tabela, text=log['status'], fg=status_color, 
                    bg=bg_color, padx=5, pady=2).grid(row=i, column=4, sticky="ew")
    
    def logout(self):
        """Faz logout e retorna para a tela de login"""
        self.controller.usuario_atual = None
        self.controller.parar_monitoramento()
        self.controller.mostrar_frame("TelaLogin")

class TelaAlertas(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg="#f0f0f0")
        self.controller = controller
        
        # Barra superior
        self.criar_barra_superior()
        
        # Área de alertas
        self.criar_area_alertas()
    
    def criar_barra_superior(self):
        """Cria a barra superior com menu de navegação"""
        barra_superior = tk.Frame(self, bg="#333333", height=50)
        barra_superior.pack(fill="x")
        
        # Título
        titulo = tk.Label(barra_superior, text="Alertas de Segurança", 
                         font=("Arial", 12, "bold"), bg="#333333", fg="white")
        titulo.pack(side="left", padx=20)
        
        # Botões de navegação
        botoes = [
            ("Dashboard", lambda: self.controller.mostrar_frame("TelaDashboard")),
            ("Logs Detalhados", lambda: self.controller.mostrar_frame("TelaDetalhes")),
            ("Análise de URLs", lambda: self.controller.mostrar_frame("TelaURLs")),
            ("Alertas", lambda: self.controller.mostrar_frame("TelaAlertas")),
            ("Relatórios", lambda: self.controller.mostrar_frame("TelaRelatorios")),
            ("Configurações", lambda: self.controller.mostrar_frame("TelaConfiguracoes")),
            ("Sair", self.logout)
        ]
        
        for texto, comando in botoes:
            botao = tk.Button(barra_superior, text=texto, command=comando,
                             bg="#333333", fg="white", bd=0, padx=10,
                             activebackground="#555555", activeforeground="white")
            botao.pack(side="left", padx=5)
    
    def criar_area_alertas(self):
        """Cria a área de alertas"""
        # Frame principal
        self.frame_principal = tk.Frame(self, bg="#f0f0f0", padx=10, pady=10)
        self.frame_principal.pack(fill="both", expand=True)
        
        # Título e botões de ação
        frame_titulo = tk.Frame(self.frame_principal, bg="#f0f0f0")
        frame_titulo.pack(fill="x", pady=5)
        
        tk.Label(frame_titulo, text="Alertas de Segurança", 
                font=("Arial", 14, "bold"), bg="#f0f0f0").pack(side="left")
        
        # Botões de ação
        botao_marcar_todos = tk.Button(frame_titulo, text="Marcar Todos como Lidos", 
                                      command=self.marcar_todos_como_lidos,
                                      bg="#4CAF50", fg="white")
        botao_marcar_todos.pack(side="right", padx=5)
        
        botao_atualizar = tk.Button(frame_titulo, text="Atualizar", 
                                   command=self.carregar_alertas,
                                   bg="#2196F3", fg="white")
        botao_atualizar.pack(side="right", padx=5)
        
        # Filtros
        frame_filtros = tk.Frame(self.frame_principal, bg="white", padx=10, pady=10)
        frame_filtros.pack(fill="x", pady=10)
        
        tk.Label(frame_filtros, text="Filtrar por:", bg="white").grid(row=0, column=0, padx=5, pady=5)
        
        # Filtro de nível
        tk.Label(frame_filtros, text="Nível:", bg="white").grid(row=0, column=1, padx=5, pady=5)
        self.filtro_nivel = ttk.Combobox(frame_filtros, values=["Todos", "Alto", "Médio", "Baixo"], width=10)
        self.filtro_nivel.current(0)
        self.filtro_nivel.grid(row=0, column=2, padx=5, pady=5)
        
        # Filtro de tipo
        tk.Label(frame_filtros, text="Tipo:", bg="white").grid(row=0, column=3, padx=5, pady=5)
        self.filtro_tipo = ttk.Combobox(frame_filtros, values=["Todos", "Falha de Login", "Horário Suspeito", "URL Restrita"], width=15)
        self.filtro_tipo.current(0)
        self.filtro_tipo.grid(row=0, column=4, padx=5, pady=5)
        
        # Filtro de status
        tk.Label(frame_filtros, text="Status:", bg="white").grid(row=0, column=5, padx=5, pady=5)
        self.filtro_status = ttk.Combobox(frame_filtros, values=["Todos", "Não Lidos", "Lidos"], width=10)
        self.filtro_status.current(0)
        self.filtro_status.grid(row=0, column=6, padx=5, pady=5)
        
        # Botão de aplicar filtros
        botao_filtrar = tk.Button(frame_filtros, text="Filtrar", 
                                 command=self.aplicar_filtros,
                                 bg="#4CAF50", fg="white")
        botao_filtrar.grid(row=0, column=7, padx=10, pady=5)
        
        # Área de alertas
        self.frame_alertas = tk.Frame(self.frame_principal, bg="#f0f0f0")
        self.frame_alertas.pack(fill="both", expand=True, pady=10)
    
    def carregar_alertas(self):
        """Carrega e exibe os alertas"""
        # Limpar área de alertas
        for widget in self.frame_alertas.winfo_children():
            widget.destroy()
        
        # Carregar alertas do banco de dados
        alertas = self.controller.carregar_alertas_db()
        
        if not alertas:
            tk.Label(self.frame_alertas, text="Nenhum alerta encontrado.", 
                    font=("Arial", 12), bg="#f0f0f0").pack(pady=50)
            return
        
        # Aplicar filtros
        alertas_filtrados = self.filtrar_alertas(alertas)
        
        if not alertas_filtrados:
            tk.Label(self.frame_alertas, text="Nenhum alerta encontrado com os filtros selecionados.", 
                    font=("Arial", 12), bg="#f0f0f0").pack(pady=50)
            return
        
        # Canvas com scrollbar para exibir os alertas
        canvas = tk.Canvas(self.frame_alertas, bg="#f0f0f0")
        scrollbar = ttk.Scrollbar(self.frame_alertas, orient="vertical", command=canvas.yview)
        
        # Frame dentro do canvas para conter os alertas
        frame_conteudo = tk.Frame(canvas, bg="#f0f0f0")
        
        # Configurar scrollbar
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Criar janela no canvas para o frame de conteúdo
        canvas.create_window((0, 0), window=frame_conteudo, anchor="nw")
        
        # Exibir cada alerta
        for i, alerta in enumerate(alertas_filtrados):
            self.criar_card_alerta(frame_conteudo, alerta, i)
        
        # Atualizar região de scroll
        frame_conteudo.update_idletasks()
        canvas.config(scrollregion=canvas.bbox("all"))
    
    def filtrar_alertas(self, alertas):
        """Aplica filtros aos alertas"""
        alertas_filtrados = alertas.copy()
        
        # Filtrar por nível
        nivel = self.filtro_nivel.get().lower()
        if nivel != "todos":
            alertas_filtrados = [a for a in alertas_filtrados if a['nivel'].lower() == nivel]
        
        # Filtrar por tipo
        tipo = self.filtro_tipo.get()
        if tipo != "Todos":
            tipo_map = {
                "Falha de Login": "falha_login",
                "Horário Suspeito": "horario_suspeito",
                "URL Restrita": "url_restrita"
            }
            tipo_filtro = tipo_map.get(tipo, "")
            if tipo_filtro:
                alertas_filtrados = [a for a in alertas_filtrados if a['tipo'] == tipo_filtro]
        
        # Filtrar por status
        status = self.filtro_status.get()
        if status == "Não Lidos":
            alertas_filtrados = [a for a in alertas_filtrados if not a.get('lido', False)]
        elif status == "Lidos":
            alertas_filtrados = [a for a in alertas_filtrados if a.get('lido', False)]
        
        return alertas_filtrados
    
    def aplicar_filtros(self):
        """Aplica os filtros selecionados"""
        self.carregar_alertas()
    
    def criar_card_alerta(self, parent, alerta, index):
        """Cria um card para exibir um alerta"""
        # Determinar cor de fundo com base no nível
        bg_color = "#ffebee" if alerta['nivel'].lower() == "alto" else "#fff8e1" if alerta['nivel'].lower() == "médio" else "#e8f5e9"
        
        # Criar frame para o alerta
        frame = tk.Frame(parent, bg=bg_color, padx=10, pady=10, bd=1, relief="solid")
        frame.pack(fill="x", pady=5, padx=10)
        
        # Ícone e título
        frame_cabecalho = tk.Frame(frame, bg=bg_color)
        frame_cabecalho.pack(fill="x")
        
        # Ícone com base no tipo
        icone = "⚠️" if alerta['nivel'].lower() == "alto" else "⚡" if alerta['nivel'].lower() == "médio" else "ℹ️"
        tk.Label(frame_cabecalho, text=icone, font=("Arial", 16), bg=bg_color).pack(side="left")
        
        # Título
        tk.Label(frame_cabecalho, text=alerta['mensagem'], 
                font=("Arial", 12, "bold"), bg=bg_color, wraplength=700, justify="left").pack(side="left", padx=10)
        
        # Status de leitura
        status_text = "Lido" if alerta.get('lido', False) else "Não Lido"
        status_color = "#9e9e9e" if alerta.get('lido', False) else "#f44336"
        tk.Label(frame_cabecalho, text=status_text, 
                font=("Arial", 10), bg=bg_color, fg=status_color).pack(side="right")
        
        # Detalhes
        frame_detalhes = tk.Frame(frame, bg=bg_color)
        frame_detalhes.pack(fill="x", pady=5)
        
        # Informações do alerta
        tk.Label(frame_detalhes, text=f"Nível: {alerta['nivel'].upper()}", 
                bg=bg_color).pack(anchor="w")
        
        tk.Label(frame_detalhes, text=f"Data/Hora: {alerta['data']} {alerta['hora']}", 
                bg=bg_color).pack(anchor="w")
        
        tk.Label(frame_detalhes, text=f"Usuário: {alerta['usuario']}", 
                bg=bg_color).pack(anchor="w")
        
        if alerta['ip'] != '':
            tk.Label(frame_detalhes, text=f"IP: {alerta['ip']}", 
                    bg=bg_color).pack(anchor="w")
        
        if alerta['url'] != '':
            tk.Label(frame_detalhes, text=f"URL: {alerta['url']}", 
                    bg=bg_color).pack(anchor="w")
        
        # Detalhes adicionais
        if alerta['detalhes']:
            tk.Label(frame_detalhes, text=alerta['detalhes'], 
                    bg=bg_color, wraplength=700, justify="left").pack(anchor="w", pady=5)
        
        # Botões de ação
        frame_botoes = tk.Frame(frame, bg=bg_color)
        frame_botoes.pack(fill="x", pady=5)
        
        # Botão para marcar como lido
        if not alerta.get('lido', False):
            botao_marcar = tk.Button(frame_botoes, text="Marcar como Lido", 
                                    command=lambda a=alerta: self.marcar_como_lido(a),
                                    bg="#4CAF50", fg="white")
            botao_marcar.pack(side="left", padx=5)
        
        # Botão para investigar (abrir tela de detalhes)
        botao_investigar = tk.Button(frame_botoes, text="Investigar", 
                                    command=lambda a=alerta: self.investigar_alerta(a),
                                    bg="#2196F3", fg="white")
        botao_investigar.pack(side="left", padx=5)
    
    def marcar_como_lido(self, alerta):
        """Marca um alerta como lido"""
        if 'id' in alerta:
            self.controller.marcar_alerta_como_lido(alerta['id'])
            self.carregar_alertas()
    
    def marcar_todos_como_lidos(self):
        """Marca todos os alertas como lidos"""
        alertas = self.controller.carregar_alertas_db()
        for alerta in alertas:
            if 'id' in alerta and not alerta.get('lido', False):
                self.controller.marcar_alerta_como_lido(alerta['id'])
        self.carregar_alertas()
    
    def investigar_alerta(self, alerta):
        """Abre uma tela para investigar o alerta em detalhes"""
        # Aqui você pode implementar a lógica para investigar o alerta
        # Por exemplo, filtrar logs relacionados ao alerta
        
        # Ir para a tela de detalhes com filtros pré-configurados
        tela_detalhes = self.controller.frames["TelaDetalhes"]
        
        # Configurar filtros
        if alerta['usuario'] != 'desconhecido':
            tela_detalhes.filtro_usuario.delete(0, tk.END)
            tela_detalhes.filtro_usuario.insert(0, alerta['usuario'])
        
        if alerta['ip'] != 'desconhecido' and alerta['ip'] != '':
            tela_detalhes.filtro_ip.delete(0, tk.END)
            tela_detalhes.filtro_ip.insert(0, alerta['ip'])
        
        if alerta['url'] != 'desconhecido' and alerta['url'] != '':
            tela_detalhes.filtro_url.delete(0, tk.END)
            tela_detalhes.filtro_url.insert(0, alerta['url'])
        
        if alerta['data']:
            tela_detalhes.filtro_data.delete(0, tk.END)
            tela_detalhes.filtro_data.insert(0, alerta['data'])
        
        # Aplicar filtros e mostrar tela
        self.controller.mostrar_frame("TelaDetalhes")
        tela_detalhes.aplicar_filtros()
        
        # Marcar como lido
        if 'id' in alerta and not alerta.get('lido', False):
            self.controller.marcar_alerta_como_lido(alerta['id'])
    
    def logout(self):
        """Faz logout e retorna para a tela de login"""
        self.controller.usuario_atual = None
        self.controller.parar_monitoramento()
        self.controller.mostrar_frame("TelaLogin")

# Iniciar a aplicação
if __name__ == "__main__":
    app = SistemaMonitoramento()
    app.mainloop()