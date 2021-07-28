# Instalando WinRM e SSH

Script em ansible para instalação do WinRM e openSSH de maneira rapida em servidores Windows

## Disclaimer

*** Esse script baixa e executa scripts de terceiros para a facilitar a isntalação desses recursos***

## Requeriments
Powershell v3.0 + 

## Install/Usage
### No Windão
- Iniciar um powershell ISE como administrador
- Clonar esse repositório (caso seu Windão tenha git, o que duvido muito),senão copie o arquvio Remote_win.ps1 para um diretório("pasta") onde o script será executado

### Running
No powershell ISE aberto como administrador, abra o script copiado e execute.

# Execução via Ansible

## Requirements

- Windão

## [Configure o WinRM no alvo, se necessário](https://docs.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management)

```powershell
PS> winrm quickconfig
 ```
 
## Usage

- Abra o Powershell ISE como administrador
- Cole o codigo do script Remote_win.ps1 em um novo arquivo
- execute
