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
