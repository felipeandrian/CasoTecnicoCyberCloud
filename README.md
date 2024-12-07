# CasoTecnicoCyberCloud
Case técnico CyberSecurity Analyst


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
