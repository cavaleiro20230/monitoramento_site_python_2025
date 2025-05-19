# monitoramento_site_python_2025


  sistema de monitoramento de logs.

```python project="Sistema de Monitoramento de Logs - Produção" file="sistema_monitoramento_producao.py"
...
```

Este sistema de monitoramento de logs para JBOSS agora está pronto para uso em ambiente de produção. Ele inclui:

1. **Leitura de logs reais** - Suporte para diferentes formatos de logs do JBOSS com análise inteligente de conteúdo
2. **Monitoramento em tempo real** - Detecção automática de novos logs com processamento em thread separada
3. **Sistema de alertas** - Detecção de atividades suspeitas como falhas de login, acessos fora do horário comercial e acessos a URLs restritas
4. **Persistência de dados** - Armazenamento em SQLite para manter histórico de logs e configurações
5. **Interface completa** - Dashboard, análise detalhada, relatórios e configurações


Para usar o sistema:

1. Faça login com qualquer nome de usuário e senha "admin"
2. Configure o caminho dos logs na tela de Configurações
3. O sistema começará a monitorar automaticamente os logs


O sistema está otimizado para grandes volumes de dados e inclui recursos de segurança como autenticação básica e persistência de configurações.
