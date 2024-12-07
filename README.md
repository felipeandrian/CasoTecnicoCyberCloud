# CasoTecnicoCyberCloud
Resposta Case técnico CyberSecurity Analyst

### Política de Segurança baseada no csse técnico para Cybersecurity Analyst

#### Introdução
Esta política de segurança é projetada para mitigar e prevenir riscos de
segurança cibernética em ambientes de rede e cloud, utilizando uma
abordagem baseada em scripts de análise de dados e práticas robustas de engenharia de segurança. A política detalha procedimentos específicos para detectar, bloquear e responder a ameaças cibernéticas, com base no arquivo de log recebido no case.

#### Objetivos
- **Proteção de Infraestrutura**: Garantir a segurança e a integridade
das redes e dos ambientes de cloud da organização.
- **Mitigação de Riscos Cibernéticos**: Implementar medidas proativas e
reativas para identificar e neutralizar ameaças cibernéticas.
- **Educação Contínua**: Promover a conscientização e a capacitação dos
colaboradores sobre práticas seguras de TI.

#### Componentes da Política de Segurança

1. **Detecção de Ameaças**
   - **Scripts de Análise de Logs e Tráfego**: Implementar scripts que
monitoram logs de acesso e tráfego de rede, identificando padrões comuns
de ataques cibernéticos. Esses scripts incluem:
     - **UA-Analyser**: Detecta mudanças frequentes no User-Agent.
     - **MultiReq-Analyser**: Monitora a taxa de requisições para
identificar comportamentos suspeitos.
     - **BadReq-Analyser**: Identifica e bloqueia caracteres especiais
usados em tentativas de ataques.
     - **CharLimit-Analyser**: Bloqueia requisições com mais de 250
caracteres.
     - **LFI-Analyser**: Monitora tentativas de inclusão de arquivos
locais (LFI).
     - **SQL-Injection-Analyser**: Detecta e bloqueia tentativas de
injeção de SQL.
     - **XSS-Analyser**: Identifica e bloqueia tentativas de Cross-Site
Scripting (XSS).

   - **Ferramentas de Monitoramento Contínuo**: Utilizar ferramentas de
monitoramento de rede em tempo real para inspecionar tráfego e gerar
alertas automáticos para atividades anômalas.

2. **Bloqueio e Prevenção**
   - **Firewalls e Listas de Bloqueio Dinâmica**: Configurar firewalls
para bloquear IPs suspeitos e manter uma lista de bloqueio dinâmica que
é atualizada automaticamente pelos scripts de análise. A política de
bloqueio deve ser escalonada, aumentando o tempo de bloqueio a cada
infração reincidente.
   - **Padrões de Desenvolvimento Seguro**: Implementar práticas de
desenvolvimento seguro, incluindo a validação e sanitização de entradas
de usuários, para prevenir ataques de injeção.

3. **Educação e Conscientização**
   - **Treinamento Regular**: Realizar treinamentos periódicos para
todos os colaboradores sobre práticas de segurança e a importância da
detecção e resposta a ameaças cibernéticas.
   - **Simulações de Ataques**: Conduzir simulações de ataques
cibernéticos para testar a eficácia das medidas de segurança e a
prontidão da equipe.

4. **Resposta a Incidentes**
   - **Equipe de Resposta a Incidentes**: Estabelecer uma equipe
dedicada com procedimentos claros para identificar, conter e remediar
violações de segurança.
   - **Relatório de Incidentes**: Desenvolver um sistema de relatório
para documentar incidentes de segurança, ações tomadas e resultados.

#### Lógica por Trás da Política

A lógica por trás desta política de segurança baseia-se em uma abordagem
de **Defesa em Profundidade**, que incorpora múltiplas camadas de
segurança para garantir uma proteção abrangente:

- **Prevenção**: Reduzir a superfície de ataque através da sanitização
de entradas de usuários e do desenvolvimento seguro de software.
- **Detecção**: Monitorar continuamente o ambiente de TI para
identificar atividades suspeitas usando scripts de análise de logs e
ferramentas de monitoramento em tempo real.
- **Resposta**: Implementar mecanismos automáticos para bloquear ameaças
detectadas, como listas de bloqueio dinâmicas e firewalls configuráveis.
- **Recuperação**: Garantir que a organização possa se recuperar
rapidamente de um ataque através de processos de resposta a incidentes
bem definidos e uma equipe dedicada.

### Identificação de Riscos

A política utiliza métodos proativos e reativos para identificar riscos:
- **Proativo**: Scripts de análise que inspecionam logs e tráfego de
rede em busca de padrões conhecidos de ataques. Ferramentas de
monitoramento em tempo real que disparam alertas para atividades
anômalas.
- **Reativo**: Equipe de resposta a incidentes que analisa e trata
incidentes de segurança conforme ocorrem. Relatórios de incidentes que
documentam e fornecem insights para melhorias contínuas.

Esta abordagem holística assegura que a organização não apenas responde
a ataques cibernéticos, mas também aprende e evolui constantemente para
melhorar suas defesas contra ameaças futuras.

### Identificação de Padrões e Anomalias

1. **Mudanças Frequentes de User-Agent**
   - **Padrão:** Mudanças frequentes no campo User-Agent de um mesmo IP
podem indicar tentativas de disfarçar a identidade do cliente para
evitar detecção.
   - **Anomalia:** Identificar IPs que mudam o User-Agent mais de 3
vezes em 5 minutos.

   **Exemplo:**
   ```plaintext
   IP: 51.208.59.112
   User-Agent: Mozilla/5.0 ... Safari/6532.20.4
   User-Agent: Opera/8.56 ... Version/12.00
   ```

2. **Alta Taxa de Requisições**
   - **Padrão:** Um número elevado de requisições de um mesmo IP em um
curto período pode indicar um ataque DDoS ou uma tentativa de enumeração
de serviços.
   - **Anomalia:** Identificar IPs que enviam mais de 40 requisições em
60 segundos.

   **Exemplo:**
   ```plaintext
   IP: 182.176.64.44
   Requisições: 50 em 60 segundos
   ```

3. **Uso de Caracteres Especiais para Bypass**
   - **Padrão:** Presença de caracteres especiais como `"` ou `'` em
URLs pode indicar tentativas de exploração de vulnerabilidades.
   - **Anomalia:** Identificar URLs que contêm padrões de caracteres
especiais ou codificados.

   **Exemplo:**
   ```plaintext
   URL: /media?file=../../etc/passwd
   URL: /seem?user=%27 OR 1=1 --
   ```

4. **Requisições Longas**
   - **Padrão:** URLs muito longas podem indicar tentativas de injeção
de comandos ou sobrecarga dos buffers do servidor.
   - **Anomalia:** Identificar URLs com mais de 250 caracteres.

   **Exemplo:**
   ```plaintext
   URL: /search?query=... (mais de 250 caracteres)
   ```

5. **Tentativas de Inclusão de Arquivos Locais (LFI)**
   - **Padrão:** Tentativas de acesso a arquivos críticos do sistema
através da URL podem indicar LFI.
   - **Anomalia:** Identificar URLs que tentam acessar `/etc/passwd`,
`/var/www/html/index.php`, etc.

   **Exemplo:**
   ```plaintext
   URL: /view?file=../../etc/passwd
   ```

6. **Injeção de SQL**
   - **Padrão:** Sequências de caracteres como `' OR 1=1`, `--`, ou `;
DROP TABLE` podem indicar tentativas de injeção de SQL.
   - **Anomalia:** Identificar requisições que contenham padrões de
injeção de SQL.

   **Exemplo:**
   ```plaintext
   URL: /login?username=admin' OR 1=1 --
   ```

7. **Scripts Entre Sites (XSS)**
   - **Padrão:** Inserção de tags `<script>` ou eventos HTML como
`onmouseover=` pode indicar tentativas de XSS.
   - **Anomalia:** Identificar URLs que contenham padrões de XSS.

   **Exemplo:**
   ```plaintext
   URL: /comment?text=<script>alert('XSS')</script>
   ```



Os seguintes scripts foram criados  para monitorar logs e tráfego de
rede, identificando padrões comuns de ataques cibernéticos baseado no csv recebido:

- **UA-Analyser**
  - **Objetivo**: Detectar mudanças frequentes no User-Agent de um mesmo
IP.
  - **Implementação**:
    ```bash
    #!/bin/bash

    UA_LOG="/tmp/ua_log.txt"
    BLOCKED_IPS_LOG="/tmp/blocked_ips.txt"
    THRESHOLD=3
    TIMEFRAME=300

    check_user_agent_changes() {
      ip="$1"
      user_agent="$2"
      current_time=$(date +%s)
      echo "$current_time $ip $user_agent" >> "$UA_LOG"
      recent_logs=$(grep "$ip" "$UA_LOG" | awk -v "time=$current_time" -v "frame=$TIMEFRAME" '$1 >= time-frame')
      ua_count=$(echo "$recent_logs" | awk '{print $3}' | sort | uniq -c | wc -l)
      if (( ua_count > THRESHOLD )); then
        block_ip "$ip"
      fi
    }

    block_ip() {
      ip="$1"
      echo "Blocked IP: $ip"
      echo "$(date +'%Y-%m-%d %H:%M:%S') $ip" >> "$BLOCKED_IPS_LOG"
    }

    echo "" > "$BLOCKED_IPS_LOG"
    if [ -z "$1" ]; then
      echo "Por favor, forneça o caminho para o arquivo CSV."
      exit 1
    fi
    while IFS=, read -r ClientIP ClientRequestHost ClientRequestMethod ClientRequestURI EdgeStartTimestamp ZoneName ClientASN ClientCountry ClientDeviceType ClientSrcPort ClientRequestBytes ClientRequestPath ClientRequestReferer ClientRequestScheme ClientRequestUserAgent
    do
      check_user_agent_changes "$ClientIP" "$ClientRequestUserAgent"
    done < <(tail -n +2 "$1")
    ```

- **MultiReq-Analyser**
  - **Objetivo**: Monitorar a taxa de requisições para identificar
comportamentos suspeitos.
  - **Implementação**:
    ```bash
    #!/bin/bash

    REQUEST_LOG="/tmp/request_log.txt"
    BLOCKED_IPS_LOG="/tmp/blocked_ips.txt"
    THRESHOLD=40
    TIMEFRAME=60

    check_request_rate() {
      ip="$1"
      current_time=$(date +%s)
      echo "$current_time $ip" >> "$REQUEST_LOG"
      recent_requests=$(grep "$ip" "$REQUEST_LOG" | awk -v "time=$current_time" -v "frame=$TIMEFRAME" '$1 >= time-frame')
      request_count=$(echo "$recent_requests" | wc -l)
      if (( request_count > THRESHOLD )); then
        block_ip "$ip"
      fi
    }

    block_ip() {
      ip="$1"
      echo "Blocked IP: $ip"
      echo "$(date +'%Y-%m-%d %H:%M:%S') $ip" >> "$BLOCKED_IPS_LOG"
    }

    echo "" > "$REQUEST_LOG"
    if [ -z "$1" ]; then
      echo "Por favor, forneça o caminho para o arquivo CSV."
      exit 1
    fi
    while IFS=, read -r ClientIP ClientRequestHost ClientRequestMethod ClientRequestURI EdgeStartTimestamp ZoneName ClientASN ClientCountry ClientDeviceType ClientSrcPort ClientRequestBytes ClientRequestPath ClientRequestReferer ClientRequestScheme ClientRequestUserAgent
    do
      check_request_rate "$ClientIP"
    done < <(tail -n +2 "$1")
    ```

- **BadReq-Analyser**
  - **Objetivo**: Identificar e bloquear caracteres especiais usados em
tentativas de ataques.
  - **Implementação**:
    ```bash
    #!/bin/bash

    BLOCKED_IPS_LOG="/tmp/blocked_ips.txt"

    PATTERNS=(
      "\"" "'" "<" ">" ";" "(" ")" "\`" "´"
      "%22" "%27" "%3C" "%3E" "%3B" "%28" "%29" "%60" "%C2%B4"
      "\042" "\047" "\074" "\076" "\073" "\050" "\051" "\140" "\264"
      "IiIi" "Jyc=" "PDw" "Pj4" "Ow==" "KCo=" "KSk=" "YA==" "4rQ="
    )

    block_ip() {
      ip="$1"
      echo "Blocked IP: $ip"
      echo "$(date +'%Y-%m-%d %H:%M:%S') $ip" >> "$BLOCKED_IPS_LOG"
    }

    echo "" > "$BLOCKED_IPS_LOG"
    if [ -z "$1" ]; then
      echo "Por favor, forneça o caminho para o arquivo CSV."
      exit 1
    fi
    while IFS=, read -r ClientIP ClientRequestHost ClientRequestMethod ClientRequestURI EdgeStartTimestamp ZoneName ClientASN ClientCountry ClientDeviceType ClientSrcPort ClientRequestBytes ClientRequestPath ClientRequestReferer ClientRequestScheme ClientRequestUserAgent
    do
      for pattern in "${PATTERNS[@]}"; do
        if echo "$ClientRequestURI" | grep -q "$pattern"; then
          block_ip "$ClientIP"
          break
        fi
      done
    done < <(tail -n +2 "$1")
    ```

- **CharLimit-Analyser**
  - **Objetivo**: Bloquear requisições com mais de 250 caracteres.
  - **Implementação**:
    ```bash
    #!/bin/bash

    BLOCKED_IPS_LOG="/tmp/blocked_ips.txt"

    block_ip() {
      ip="$1"
      echo "Blocked IP: $ip"
      echo "$(date +'%Y-%m-%d %H:%M:%S') $ip" >> "$BLOCKED_IPS_LOG"
    }

    echo "" > "$BLOCKED_IPS_LOG"
    if [ -z "$1" ]; então
      echo "Por favor, forneça o caminho para o arquivo CSV."
      exit 1
    fi
    while IFS=, read -r ClientIP ClientRequestHost ClientRequestMethod ClientRequestURI EdgeStartTimestamp ZoneName ClientASN ClientCountry ClientDeviceType ClientSrcPort ClientRequestBytes ClientRequestPath ClientRequestReferer ClientRequestScheme ClientRequestUserAgent
    do
      if (( ${#ClientRequestURI} > 250 )); então
        block_ip "$ClientIP"
      fi
    done < <(tail -n +2 "$1")
    ```

- **LFI-Analyser**
  - **Objetivo**: Monitorar tentativas de inclusão de arquivos locais
(LFI).
  - **Implementação**:
    ```bash
    #!/bin/bash

    BLOCKED_IPS_LOG="/tmp/blocked_ips.txt"

    PATTERNS=(
      "/etc/passwd"
      "/var/www/html/index.php"
      "../"
      "..%2F"
      "..%252f"
      "%c0%af"
    )

    block_ip() {
      ip="$1"
      echo "Blocked IP: $ip"
      echo "$(date +'%Y-%m-%d %H:%M:%S') $ip" >> "$BLOCKED_IPS_LOG"
    }

    echo "" > "$BLOCKED_IPS_LOG"
    if [ -z "$1" ]; então
      echo "Por favor, forneça o caminho para o arquivo CSV."
      exit 1
    fi
    while IFS=, read -r ClientIP ClientRequestHost ClientRequestMethod ClientRequestURI EdgeStartTimestamp ZoneName ClientASN ClientCountry ClientDeviceType ClientSrcPort ClientRequestBytes ClientRequestPath ClientRequestReferer ClientRequestScheme ClientRequestUserAgent
    do
      for pattern in "${PATTERNS[@]}"; do
        if echo "$ClientRequestURI" | grep -q "$pattern"; então
          block_ip "$ClientIP"
          break
        fi
      done
    done < <(tail -n +2 "$1")
    ```

- **SQL-Injection-Analyser**
  - **Objetivo**: Detectar e bloquear tentativas de injeção de SQL.
  - **Implementação**:
    ```bash
    #!/bin/bash
    # Arquivo para armazenar IPs bloqueados
    BLOCKED_IPS_LOG="/tmp/blocked_ips.txt"
    # Padrões de SQL Injection a serem bloqueados
    PATTERNS=(
    "' OR 1=1"
      "' OR 'a'='a"
      "' OR ''='"
      "--"
      "; DROP TABLE"
      "; SELECT"
      "%27 OR 1=1"
      "%27 OR 'a'='a"
      "%27 OR ''='"
      "--%20"
      "%3B DROP TABLE")
    # Função para bloquear o IP
    block_ip() {
      ip="$1"
      echo "Blocked IP: $ip"
      echo "$(date +'%Y-%m-%d %H:%M:%S') $ip" >> "$BLOCKED_IPS_LOG"
    }
    # Inicializar log de IPs bloqueados
    echo "" > "$BLOCKED_IPS_LOG"
    # Processar dados do CSV
    while IFS=, read -r ClientIP ClientRequestHost ClientRequestMethod ClientRequestURI EdgeStartTimestamp ZoneName ClientASN ClientCountry ClientDeviceType ClientSrcPort ClientRequestBytes ClientRequestPath ClientRequestReferer ClientRequestScheme ClientRequestUserAgent
    do
     for pattern in "${PATTERNS[@]}"; do
    if echo "$ClientRequestURI" | grep -q "$pattern"; then
      block_ip "$ClientIP"
      break
    fi
     done
    done < "$1"
    ```

    - **XSS-Analyser**
  - **Objetivo**: Detectar e bloquear tentativas de Cross-site Scripting (XSS).
  - **Implementação**:
    ```bash
    #!/bin/bash
    # Arquivo para armazenar IPs bloqueados
    BLOCKED_IPS_LOG="/tmp/blocked_ips.txt"
    # Padrões de XSS a serem bloqueados
    PATTERNS=(
    "<script>"
      "</script>"
      "onmouseover="
      "onerror="
      "javascript:"
      "vbscript:"
      "%3Cscript%3E"
      "%3C%2Fscript%3E"
      "%3Conmouseover%3D"
      "%3Conerror%3D")
    # Função para bloquear o IP
    block_ip() {
      ip="$1"
      echo "Blocked IP: $ip"
      echo "$(date +'%Y-%m-%d %H:%M:%S') $ip" >> "$BLOCKED_IPS_LOG"
    }
    # Inicializar log de IPs bloqueados
    echo "" > "$BLOCKED_IPS_LOG"
    # Processar dados do CSV
    while IFS=, read -r ClientIP ClientRequestHost ClientRequestMethod ClientRequestURI EdgeStartTimestamp ZoneName ClientASN ClientCountry ClientDeviceType ClientSrcPort ClientRequestBytes ClientRequestPath ClientRequestReferer ClientRequestScheme ClientRequestUserAgent
    do
      for pattern in "${PATTERNS[@]}"; do
    if echo "$ClientRequestURI" | grep -q "$pattern"; then
      block_ip "$ClientIP"
      break
    fi
     done
    done < "$1"
    ```

- **BAN Manager**
- **Objetivo**:
O objetivo do `ban_manager.sh` é gerenciar o banimento de IPs que são
detectados como maliciosos pelos diversos scripts de análise
(`ua-analyser.sh`, `multireq_analyser.sh`, `badreq_analyser.sh`, etc.).
Ele bloqueia IPs temporariamente e gere uma lista de IPs banidos,
escalando o tempo de banimento para IPs reincidentes.

#### Componentes do Script

1. **Arquivo de Log de IPs Bloqueados** (`/tmp/blocked_ips.txt`):
   - Registra os IPs bloqueados, o tempo em que foram bloqueados e o
tempo de banimento.
   - Formato de registro: `IP | Timestamp de Bloqueio | Tempo de
Banimento`

2. **Arquivo de Histórico de Banimentos** (`/tmp/ban_history.txt`):
   - Mantém um histórico dos IPs bloqueados e a contagem de vezes que
foram banidos.
   - Formato de registro: `IP | Contagem de Banimentos`

3. **Arquivo Temporário para IPs Desbloqueados**
(`/tmp/unblocked_ips.txt`):
   - Armazena IPs que tiveram seu tempo de banimento expirado durante a
execução do script.

#### Lógica e Implementação

`ban_manager.sh`:

```bash
#!/bin/bash

# Arquivo para armazenar os IPs bloqueados e seus tempos de banimento
BLOCKED_IPS_LOG="/tmp/blocked_ips.txt"
# Arquivo para armazenar o histórico de banimentos dos IPs
BAN_HISTORY_LOG="/tmp/ban_history.txt"
# Arquivo temporário para IPs desbloqueados
UNBLOCKED_IPS_LOG="/tmp/unblocked_ips.txt"

# Função para bloquear um IP
block_ip() {
  ip="$1"
  current_time=$(date +%s)
  
  # Verificar se o IP já foi banido anteriormente
  if grep -q "$ip" "$BAN_HISTORY_LOG"; then
    # Incrementar exponencialmente o tempo de banimento
    ban_count=$(grep "$ip" "$BAN_HISTORY_LOG" | awk '{print $2}')
    ban_count=$((ban_count + 1))
    ban_time=$((60 * 2 ** (ban_count - 1)))
    sed -i "/$ip/d" "$BAN_HISTORY_LOG"
  else
    # Tempo inicial de banimento (em segundos)
    ban_count=1
    ban_time=60
  fi

  # Adicionar ou atualizar o IP no histórico de banimentos
  echo "$ip $ban_count" >> "$BAN_HISTORY_LOG"

  # Adicionar o IP ao log de IPs bloqueados
  echo "$ip $current_time $ban_time" >> "$BLOCKED_IPS_LOG"
  echo "Blocked IP: $ip for $ban_time seconds"
}

# Função para desbloquear IPs cujo tempo de banimento expirou
unblock_ips() {
  current_time=$(date +%s)
  while read -r line; do
    ip=$(echo "$line" | awk '{print $1}')
    block_time=$(echo "$line" | awk '{print $2}')
    ban_time=$(echo "$line" | awk '{print $3}')
    if (( current_time >= block_time + ban_time )); then
      echo "$(date +'%Y-%m-%d %H:%M:%S') Unblocked IP: $ip"
    else
      echo "$line" >> "$UNBLOCKED_IPS_LOG"
    fi
  done < "$BLOCKED_IPS_LOG"
  mv "$UNBLOCKED_IPS_LOG" "$BLOCKED_IPS_LOG"
}

# Loop principal para monitorar e gerenciar IPs
while true; do
  unblock_ips
  sleep 10 # Verificar a cada 10 segundos
done
```

### Explicação dos Componentes e Lógica

1. **Definição de Variáveis**:
   - `BLOCKED_IPS_LOG`: Caminho para o arquivo que armazena os IPs
bloqueados e seus tempos de banimento.
   - `BAN_HISTORY_LOG`: Caminho para o arquivo que armazena o histórico
de banimentos dos IPs.
   - `UNBLOCKED_IPS_LOG`: Caminho para o arquivo temporário que armazena
os IPs desbloqueados.

2. **Função `block_ip`**:
   - **Entrada**: IP do cliente.
   - Obtém o timestamp atual.
   - Verifica se o IP já foi banido anteriormente:
     - **Se sim**: Incrementa a contagem de banimentos (`ban_count`) e
calcula o novo tempo de banimento (`ban_time`) com um incremento
exponencial.
     - **Se não**: Define a contagem de banimentos inicial
(`ban_count=1`) e o tempo de banimento inicial (`ban_time=60` segundos).
   - Atualiza o histórico de banimentos (`BAN_HISTORY_LOG`) com o novo
`ban_count`.
   - Adiciona o IP ao log de IPs bloqueados (`BLOCKED_IPS_LOG`) com o
timestamp atual e o tempo de banimento.

3. **Função `unblock_ips`**:
   - Obtém o timestamp atual.
   - Lê cada linha do log de IPs bloqueados (`BLOCKED_IPS_LOG`):
     - Extrai o IP, o timestamp de bloqueio e o tempo de banimento.
     - Verifica se o tempo de banimento expirou (timestamp atual >=
timestamp de bloqueio + tempo de banimento):
       - **Se sim**: Desbloqueia o IP e registra a ação.
       - **Se não**: Mantém o registro no arquivo temporário de IPs
desbloqueados (`UNBLOCKED_IPS_LOG`).
   - Substitui o log de IPs bloqueados pelo arquivo temporário de IPs
desbloqueados.

4. **Loop Principal**:
   - Executa a função `unblock_ips` a cada 10 segundos para verificar e
atualizar o status dos IPs bloqueados.

O `ban_manager.sh` é um script essencial para gerenciar o bloqueio de
IPs maliciosos de forma automatizada e escalonada. Ele assegura que IPs
suspeitos sejam bloqueados por períodos incrementais, evitando ataques
recorrentes e minimizando o impacto no sistema. O uso de logs para
registrar as ações permite a rastreabilidade e a análise futura das
atividades de segurança.


- **TEST ANALYZERS**
- **Objetivo**:
Ele centraliza a gestão de múltiplos scripts de análise de segurança,
automatizando a detecção, o bloqueio e a resposta a atividades
maliciosas. 
### Implementação do Script `test_analyzers.sh`

```bash
#!/bin/bash

# Caminhos para os scripts individuais
UA_ANALYSER="./ua-analyser.sh"
MULTIREQ_ANALYSER="./multireq_analyser.sh"
BADREQ_ANALYSER="./badreq_analyser.sh"
CHARLIMIT_ANALYSER="./charlimit_analyser.sh"
LFI_ANALYSER="./lfi_analyser.sh"
SQL_INJECTION_ANALYSER="./sql_injection_analyser.sh"
XSS_ANALYSER="./xss_analyser.sh"
BAN_MANAGER="./ban_manager.sh"

# Caminho para o arquivo CSV de teste
CSV_FILE="test_data.csv"

# Função para iniciar um script
start_script() {
  script=$1
  pid_file=$2
  nohup "$script" "$CSV_FILE" > /dev/null 2>&1 &
  echo $! > "$pid_file"
  echo "$script started."
}

# Função para parar um script
stop_script() {
  pid_file=$1
  if [ -f "$pid_file" ]; then
    kill $(cat "$pid_file") 2>/dev/null
    rm "$pid_file"
    echo "$(basename $pid_file .pid) stopped."
  else
    echo "$(basename $pid_file .pid) is not running."
  fi
}

# Função para verificar o status de um script
status_script() {
  pid_file=$1
  if [ -f "$pid_file" ]; then
    if kill -0 $(cat "$pid_file") 2>/dev/null; then
      echo "$(basename $pid_file .pid) is running."
    else
      echo "$(basename $pid_file .pid) is not running."
    fi
  else
    echo "$(basename $pid_file .pid) is not running."
  fi
}

# Comando principal
case "$1" in
  start)
    case "$2" in
      ua-analyser)
        start_script "$UA_ANALYSER" "/tmp/ua-analyser.pid"
        ;;
      multireq-analyser)
        start_script "$MULTIREQ_ANALYSER" "/tmp/multireq_analyser.pid"
        ;;
      badreq-analyser)
        start_script "$BADREQ_ANALYSER" "/tmp/badreq_analyser.pid"
        ;;
      charlimit-analyser)
        start_script "$CHARLIMIT_ANALYSER" "/tmp/charlimit_analyser.pid"
        ;;
      lfi-analyser)
        start_script "$LFI_ANALYSER" "/tmp/lfi_analyser.pid"
        ;;
      sql-injection-analyser)
        start_script "$SQL_INJECTION_ANALYSER"
"/tmp/sql_injection_analyser.pid"
        ;;
      xss-analyser)
        start_script "$XSS_ANALYSER" "/tmp/xss_analyser.pid"
        ;;
      ban-manager)
        start_script "$BAN_MANAGER" "/tmp/ban_manager.pid"
        ;;
      all)
        start_script "$UA_ANALYSER" "/tmp/ua-analyser.pid"
        start_script "$MULTIREQ_ANALYSER" "/tmp/multireq_analyser.pid"
        start_script "$BADREQ_ANALYSER" "/tmp/badreq_analyser.pid"
        start_script "$CHARLIMIT_ANALYSER" "/tmp/charlimit_analyser.pid"
        start_script "$LFI_ANALYSER" "/tmp/lfi_analyser.pid"
        start_script "$SQL_INJECTION_ANALYSER"
"/tmp/sql_injection_analyser.pid"
        start_script "$XSS_ANALYSER" "/tmp/xss_analyser.pid"
        start_script "$BAN_MANAGER" "/tmp/ban_manager.pid"
        ;;
      *)
        echo "Usage: $0 start
{ua-analyser|multireq-analyser|badreq-analyser|charlimit-analyser|lfi-analyser|sql-injection-analyser|xss-analyser|ban-manager|all}"
        ;;
    esac
    ;;
  stop)
    case "$2" in
      ua-analyser)
        stop_script "/tmp/ua-analyser.pid"
        ;;
      multireq-analyser)
        stop_script "/tmp/multireq_analyser.pid"
        ;;
      badreq-analyser)
        stop_script "/tmp/badreq_analyser.pid"
        ;;
      charlimit-analyser)
        stop_script "/tmp/charlimit_analyser.pid"
        ;;
      lfi-analyser)
        stop_script "/tmp/lfi_analyser.pid"
        ;;
      sql-injection-analyser)
        stop_script "/tmp/sql_injection_analyser.pid"
        ;;
      xss-analyser)
        stop_script "/tmp/xss_analyser.pid"
        ;;
      ban-manager)
        stop_script "/tmp/ban_manager.pid"
        ;;
      all)
        stop_script "/tmp/ua-analyser.pid"
        stop_script "/tmp/multireq_analyser.pid"
        stop_script "/tmp/badreq_analyser.pid"
        stop_script "/tmp/charlimit_analyser.pid"
        stop_script "/tmp/lfi_analyser.pid"
        stop_script "/tmp/sql_injection_analyser.pid"
        stop_script "/tmp/xss_analyser.pid"
        stop_script "/tmp/ban_manager.pid"
        ;;
      *)
        echo "Usage: $0 stop
{ua-analyser|multireq-analyser|badreq-analyser|charlimit-analyser|lfi-analyser|sql-injection-analyser|xss-analyser|ban-manager|all}"
        ;;
    esac
    ;;
  status)
    case "$2" in
      ua-analyser)
        status_script "/tmp/ua-analyser.pid"
        ;;
      multireq-analyser)
        status_script "/tmp/multireq_analyser.pid"
        ;;
      badreq-analyser)
        status_script "/tmp/badreq_analyser.pid"
        ;;
      charlimit-analyser)
        status_script "/tmp/charlimit_analyser.pid"
        ;;
      lfi-analyser)
        status_script "/tmp/lfi_analyser.pid"
        ;;
      sql-injection-analyser)
        status_script "/tmp/sql_injection_analyser.pid"
        ;;
      xss-analyser)
        status_script "/tmp/xss_analyser.pid"
        ;;
      ban-manager)
        status_script "/tmp/ban_manager.pid"
        ;;
      all)
        status_script "/tmp/ua-analyser.pid"
        status_script "/tmp/multireq_analyser.pid"
        status_script "/tmp/badreq_analyser.pid"
        status_script "/tmp/charlimit_analyser.pid"
        status_script "/tmp/lfi_analyser.pid"
        status_script "/tmp/sql_injection_analyser.pid"
        status_script "/tmp/xss_analyser.pid"
        status_script "/tmp/ban_manager.pid"
        ;;
      *)
        echo "Usage: $0 status
{ua-analyser|multireq-analyser|badreq-analyser|charlimit-analyser|lfi-analyser|sql-injection-analyser|xss-analyser|ban-manager|all}"
        ;;
    esac
    ;;
  *)
    echo "Usage: $0 {start|stop|status}
{ua-analyser|multireq-analyser|badreq-analyser|charlimit-analyser|lfi-analyser|sql-injection-analyser|xss-analyser|ban-manager|all}"
    exit 1
esac
```

Gestão Centralizada: O script permite gerenciar múltiplos scripts de
análise a partir de um único ponto de controle. Isso facilita o
gerenciamento e a execução de tarefas de segurança sem a necessidade de
iniciar ou monitorar manualmente cada script individualmente.

Automação de Processos: Automatiza a leitura dos dados do CSV e a
execução dos scripts de análise, economizando tempo e reduzindo o
esforço manual necessário para manter a segurança da rede. A automação
garante que as análises sejam realizadas de forma consistente e
contínua.

Facilidade de Uso: O script oferece comandos simples (start, stop,
status) para iniciar, parar e verificar o status dos scripts de análise,
tornando-o acessível e fácil de usar até mesmo para administradores de
rede com menos experiência técnica.

Escalabilidade: Pode ser facilmente estendido para incluir novos scripts
de análise à medida que surgem novas ameaças ou requisitos de segurança.
Isso garante que a solução possa crescer junto com as necessidades da
organização.

Registro de Resultados: Todos os resultados das análises são registrados
em um arquivo de log, permitindo uma fácil auditoria e rastreamento das
ações realizadas. Isso é crucial para entender a natureza das ameaças
enfrentadas e para documentar as respostas a incidentes.

### Modificaçõe para ambiente de produção

Podemos modificar o test_analyzers.sh para analisar dados em tempo real
usando tcpdump, precisaremos ajustar o script para capturar e processar
pacotes de rede diretamente em tempo real, em vez de ler dados de um
arquivo CSV. Aqui está um passo a passo de como fazer isso:
Passos para Modificar o test_analyzers.sh

### Captura de Pacotes com tcpdump:

Use tcpdump para capturar pacotes e redirecioná-los para um
pipeline que os scripts de análise possam processar em tempo real.

### Leitura de Dados em Tempo Real:

Modifique os scripts de análise para ler os dados de entrada
diretamente do pipeline, ao invés de ler de um arquivo CSV.

Implementação Completa do Script test_analyzers.sh

Vamos iniciar capturando pacotes de rede em tempo real e redirecionando
a saída para os scripts de análise.
Captura de Pacotes com tcpdump

Você pode usar o seguinte comando tcpdump para capturar pacotes de rede
e redirecioná-los para um pipeline:

```Bash
tcpdump -l -i eth0 -w - | tcpdump -r - -l -A | ./test_analyzers.sh start
```
 -l: Desativa o buffer de linha, para que você obtenha saída em tempo
real.

 -i eth0: Especifica a interface de rede a ser monitorada (substitua
eth0 pela interface apropriada).

  -w -: Especifica que a saída deve ser escrita no stdout.

 -r -: Especifica que a entrada deve ser lida do stdin.

 -A: Exibe o conteúdo do pacote ASCII.

###Modificação do test_analyzers.sh

Vamos modificar o test_analyzers.sh para processar a entrada diretamente
do pipeline.

```Bash
#!/bin/bash

# Caminhos para os scripts individuais
UA_ANALYSER="./ua-analyser.sh"
MULTIREQ_ANALYSER="./multireq_analyser.sh"
BADREQ_ANALYSER="./badreq_analyser.sh"
CHARLIMIT_ANALYSER="./charlimit_analyser.sh"
LFI_ANALYSER="./lfi_analyser.sh"
SQL_INJECTION_ANALYSER="./sql_injection_analyser.sh"
XSS_ANALYSER="./xss_analyser.sh"
BAN_MANAGER="./ban_manager.sh"

# Função para iniciar um script
start_script() {
  script=$1
  pid_file=$2
  nohup "$script" > /dev/null 2>&1 &
  echo $! > "$pid_file"
  echo "$script started."
}

# Função para parar um script
stop_script() {
  pid_file=$1
  if [ -f "$pid_file" ]; then
    kill $(cat "$pid_file") 2>/dev/null
    rm "$pid_file"
    echo "$(basename $pid_file .pid) stopped."
  else
    echo "$(basename $pid_file .pid) is not running."
  fi
}

# Função para verificar o status de um script
status_script() {
  pid_file=$1
  if [ -f "$pid_file" ]; então
    if kill -0 $(cat "$pid_file") 2>/dev/null; então
      echo "$(basename $pid_file .pid) is running."
    else
      echo "$(basename $pid_file .pid) is not running."
    fi
  else
    echo "$(basename $pid_file .pid) is not running."
  fi
}

# Função para capturar e processar pacotes em tempo real com tcpdump
capture_packets() {
  nohup tcpdump -l -i eth0 -w - | tcpdump -r - -l -A | while read -r
line; então
    # Passe a linha capturada para cada script de análise
    echo "$line" | bash $UA_ANALYSER
    echo "$line" | bash $MULTIREQ_ANALYSER
    echo "$line" | bash $BADREQ_ANALYSER
    echo "$line" | bash $CHARLIMIT_ANALYSER
    echo "$line" | bash $LFI_ANALYSER
    echo "$line" | bash $SQL_INJECTION_ANALYSER
    echo "$line" | bash $XSS_ANALYSER
    echo "$line" | bash $BAN_MANAGER
  done > /dev/null 2>&1 &
  echo $! > "/tmp/tcpdump.pid"
}

..........
```

