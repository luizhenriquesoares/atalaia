"""Finding catalogue: classification and remediation guidance for every check.

Texts shown to customers are in Brazilian Portuguese (the product's first market).
"""
from __future__ import annotations

from dataclasses import dataclass, field

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass(frozen=True)
class Vuln:
    id: str
    title: str
    severity: str
    cwe: int | None
    owasp: str
    cvss: float
    description: str
    remediation: str
    references: tuple[str, ...] = field(default_factory=tuple)


A01 = "A01:2021 Broken Access Control"
A02 = "A02:2021 Cryptographic Failures"
A03 = "A03:2021 Injection"
A05 = "A05:2021 Security Misconfiguration"
A06 = "A06:2021 Vulnerable and Outdated Components"
A07 = "A07:2021 Identification and Authentication Failures"
A08 = "A08:2021 Software and Data Integrity Failures"

_ITEMS = [
    # ---- Injection -------------------------------------------------------
    Vuln("xss-reflected", "Cross-Site Scripting (XSS) refletido", "high", 79, A03, 7.1,
         "O valor de um parâmetro é devolvido na resposta HTML sem codificação adequada, "
         "permitindo que um atacante injete marcação/JavaScript executado no navegador da vítima.",
         "Codifique a saída conforme o contexto (HTML, atributo, JavaScript, URL) usando o mecanismo "
         "de escape do framework. Valide a entrada por lista de permissão e adote uma "
         "Content-Security-Policy restritiva como defesa em profundidade.",
         ("https://owasp.org/www-community/attacks/xss/",
          "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html")),
    Vuln("xss-dom", "Cross-Site Scripting (XSS) baseado em DOM", "high", 79, A03, 7.1,
         "O JavaScript da página insere um valor controlado pelo usuário (parâmetro ou fragmento da URL) "
         "no DOM por um destino inseguro, como innerHTML ou document.write. A execução foi comprovada em "
         "um navegador real.",
         "Use destinos seguros (textContent, setAttribute em atributos não executáveis) ou sanitize o "
         "HTML com uma biblioteca mantida, como DOMPurify. Adote Trusted Types e uma "
         "Content-Security-Policy restritiva.",
         ("https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",)),
    Vuln("xss-stored", "Cross-Site Scripting (XSS) armazenado", "high", 79, A03, 8.7,
         "Um valor enviado à aplicação foi gravado e depois exibido em outra página sem codificação. "
         "Todo visitante dessa página executa a marcação injetada.",
         "Codifique a saída conforme o contexto em todos os pontos onde dados armazenados são exibidos, "
         "valide a entrada no recebimento e adote uma Content-Security-Policy restritiva.",
         ("https://owasp.org/www-community/attacks/xss/#stored-xss-attacks",)),
    Vuln("crlf-injection", "Injeção de cabeçalho HTTP (CRLF)", "medium", 113, A03, 6.1,
         "Quebras de linha enviadas no parâmetro chegam aos cabeçalhos da resposta, permitindo criar "
         "cabeçalhos arbitrários (fixação de sessão, envenenamento de cache, XSS).",
         "Nunca copie entrada do usuário para cabeçalhos de resposta sem remover CR e LF. Use as funções "
         "do framework para redirecionamentos e cookies e mantenha o servidor atualizado.",
         ("https://owasp.org/www-community/vulnerabilities/CRLF_Injection",)),
    Vuln("host-header-injection", "Envenenamento por cabeçalho de host", "medium", 644, A05, 5.4,
         "A aplicação usa o valor de X-Forwarded-Host para montar URLs absolutas na resposta. Isso permite "
         "envenenar caches e links enviados por e-mail, como os de redefinição de senha.",
         "Monte URLs absolutas a partir de um nome de host fixo na configuração. Aceite X-Forwarded-Host "
         "apenas de proxies confiáveis e valide-o contra uma lista de permissão.",
         ("https://portswigger.net/web-security/host-header",)),
    Vuln("jwt-insecure", "Token JWT com assinatura insegura", "high", 347, A02, 8.1,
         "A aplicação emite tokens JWT sem assinatura (alg none) ou assinados com um segredo trivial, "
         "o que permite forjar tokens e assumir a identidade de outros usuários.",
         "Rejeite tokens com alg none, fixe o algoritmo esperado na validação e use um segredo aleatório "
         "de pelo menos 256 bits ou chaves assimétricas. Rotacione o segredo atual.",
         ("https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",)),
    Vuln("session-in-url", "Identificador de sessão na URL", "medium", 598, A07, 5.3,
         "A aplicação coloca identificadores de sessão ou tokens em URLs, que ficam em históricos, logs "
         "de servidores e cabeçalhos Referer.",
         "Transporte a sessão apenas em cookies com Secure, HttpOnly e SameSite, ou no cabeçalho "
         "Authorization.", ()),
    Vuln("sqli-error", "Injeção de SQL (baseada em erro)", "critical", 89, A03, 9.8,
         "Um caractere de controle de SQL no parâmetro provocou uma mensagem de erro do banco de dados, "
         "indicando que a entrada é concatenada na consulta sem parametrização.",
         "Use consultas parametrizadas (prepared statements) ou um ORM em todas as consultas. "
         "Nunca concatene entrada do usuário em SQL. Desative mensagens de erro detalhadas em produção "
         "e aplique o princípio do menor privilégio na conta do banco.",
         ("https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",)),
    Vuln("sqli-boolean", "Injeção de SQL (baseada em booleano)", "critical", 89, A03, 9.8,
         "A resposta muda de forma consistente quando condições SQL verdadeiras e falsas são anexadas ao "
         "parâmetro, indicando que a entrada altera a lógica da consulta.",
         "Use consultas parametrizadas (prepared statements) ou um ORM em todas as consultas e valide "
         "o tipo dos parâmetros (por exemplo, converta identificadores para inteiro).",
         ("https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",)),
    Vuln("ssti", "Injeção de template no servidor (SSTI)", "critical", 1336, A03, 9.8,
         "Uma expressão aritmética enviada no parâmetro foi avaliada pelo motor de templates do servidor. "
         "Esse comportamento normalmente permite execução remota de código.",
         "Nunca construa templates a partir de entrada do usuário. Passe os dados como variáveis de "
         "contexto para templates estáticos e use ambientes sandbox quando templates dinâmicos forem "
         "inevitáveis.",
         ("https://portswigger.net/web-security/server-side-template-injection",)),
    Vuln("path-traversal", "Path traversal / leitura arbitrária de arquivos", "high", 22, A01, 7.5,
         "O parâmetro permite escapar do diretório esperado e ler arquivos do sistema operacional.",
         "Não use entrada do usuário para montar caminhos de arquivos. Mapeie identificadores para "
         "arquivos por lista de permissão, normalize o caminho e confirme que ele permanece dentro do "
         "diretório base antes de abrir.",
         ("https://owasp.org/www-community/attacks/Path_Traversal",)),
    Vuln("open-redirect", "Redirecionamento aberto", "medium", 601, A01, 6.1,
         "A aplicação redireciona para um domínio externo arbitrário informado em um parâmetro, o que "
         "facilita phishing e roubo de tokens em fluxos de autenticação.",
         "Aceite apenas caminhos relativos ou destinos de uma lista de permissão. Rejeite URLs absolutas "
         "e variantes como //host e \\\\host.",
         ("https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",)),
    # ---- Exposure ---------------------------------------------------------
    Vuln("exposed-git", "Repositório Git exposto", "high", 538, A05, 7.5,
         "O diretório .git está acessível pela web. Um atacante pode reconstruir o código-fonte e o "
         "histórico, incluindo credenciais já removidas.",
         "Remova o diretório .git do servidor web ou bloqueie o acesso a caminhos iniciados por ponto. "
         "Rotacione qualquer segredo que já tenha sido versionado.",
         ("https://owasp.org/www-project-web-security-testing-guide/",)),
    Vuln("exposed-env", "Arquivo de ambiente (.env) exposto", "critical", 200, A05, 9.1,
         "Um arquivo de configuração com variáveis de ambiente está acessível publicamente. Esses "
         "arquivos costumam conter senhas de banco, chaves de API e segredos de assinatura.",
         "Remova o arquivo da raiz web, bloqueie arquivos iniciados por ponto no servidor e rotacione "
         "imediatamente todos os segredos contidos nele.", ()),
    Vuln("exposed-backup", "Arquivo de backup ou dump exposto", "high", 530, A05, 7.5,
         "Um arquivo de backup, dump de banco de dados ou cópia de configuração está acessível "
         "publicamente.",
         "Remova backups da raiz web e armazene-os em local sem acesso público. Rotacione credenciais "
         "contidas no arquivo.", ()),
    Vuln("exposed-private-key", "Chave privada exposta", "critical", 321, A02, 9.1,
         "Um arquivo contendo chave privada está acessível publicamente.",
         "Remova o arquivo, revogue e substitua a chave e os certificados associados.", ()),
    Vuln("exposed-debug", "Endpoint de diagnóstico/depuração exposto", "medium", 215, A05, 5.3,
         "Um endpoint de diagnóstico (phpinfo, server-status, actuator, pprof etc.) está acessível sem "
         "autenticação e revela detalhes internos do ambiente.",
         "Desative endpoints de diagnóstico em produção ou restrinja-os por autenticação e rede.", ()),
    Vuln("exposed-api-docs", "Documentação de API exposta", "info", 200, A05, 0.0,
         "A especificação OpenAPI/Swagger está publicamente acessível. Isso não é uma vulnerabilidade "
         "por si só, mas amplia o conhecimento do atacante sobre a superfície de ataque.",
         "Confirme que a exposição é intencional. Caso contrário, restrinja o acesso por autenticação.", ()),
    Vuln("graphql-introspection", "Introspecção GraphQL habilitada", "low", 200, A05, 3.7,
         "O endpoint GraphQL responde a consultas de introspecção, revelando todo o esquema da API.",
         "Desative a introspecção em produção ou restrinja-a a usuários autenticados e autorizados.",
         ("https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",)),
    Vuln("directory-listing", "Listagem de diretório habilitada", "medium", 548, A05, 5.3,
         "O servidor lista o conteúdo de diretórios, expondo arquivos que não deveriam ser descobertos.",
         "Desative a listagem automática (por exemplo, `autoindex off` no nginx ou `Options -Indexes` "
         "no Apache).", ()),
    Vuln("secret-in-response", "Segredo exposto no conteúdo da página", "high", 798, A02, 7.5,
         "A resposta contém um valor com formato de credencial (chave de API, token ou chave privada).",
         "Remova o segredo do código entregue ao cliente, rotacione-o e mova chamadas que precisam "
         "dele para o backend.", ()),
    Vuln("error-disclosure", "Mensagem de erro detalhada / stack trace", "low", 209, A05, 3.7,
         "A aplicação devolve mensagens de erro técnicas ou stack traces, revelando tecnologia, "
         "caminhos e trechos de código.",
         "Desative o modo de depuração em produção e devolva páginas de erro genéricas, registrando "
         "os detalhes apenas no servidor.", ()),
    Vuln("internal-ip-disclosure", "Endereço IP interno divulgado", "low", 200, A05, 2.6,
         "A resposta contém endereços IP de redes privadas, revelando a topologia interna.",
         "Remova endereços internos de respostas, cabeçalhos e comentários.", ()),
    Vuln("version-disclosure", "Divulgação de versão de software em cabeçalhos", "low", 200, A05, 2.6,
         "Cabeçalhos de resposta revelam o produto e a versão do servidor ou framework, facilitando a "
         "busca por vulnerabilidades conhecidas.",
         "Remova ou generalize os cabeçalhos Server, X-Powered-By e similares.", ()),
    # ---- Headers ----------------------------------------------------------
    Vuln("missing-hsts", "Cabeçalho Strict-Transport-Security ausente", "medium", 319, A05, 4.8,
         "Sem HSTS, o navegador pode ser induzido a acessar o site por HTTP, permitindo interceptação.",
         "Envie `Strict-Transport-Security: max-age=31536000; includeSubDomains` em todas as respostas "
         "HTTPS.", ("https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",)),
    Vuln("weak-hsts", "Strict-Transport-Security com max-age curto", "low", 319, A05, 2.6,
         "O max-age do HSTS é inferior a 180 dias, reduzindo a proteção.",
         "Use max-age de pelo menos 31536000 (um ano).", ()),
    Vuln("missing-csp", "Content-Security-Policy ausente", "medium", 693, A05, 4.3,
         "Sem CSP não há defesa em profundidade contra XSS e injeção de conteúdo.",
         "Defina uma Content-Security-Policy restritiva, de preferência baseada em nonces ou hashes, "
         "sem 'unsafe-inline' e 'unsafe-eval'.",
         ("https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",)),
    Vuln("weak-csp", "Content-Security-Policy permissiva", "low", 693, A05, 3.1,
         "A política contém diretivas que anulam boa parte da proteção ('unsafe-inline', 'unsafe-eval' "
         "ou origens curinga em scripts).",
         "Substitua 'unsafe-inline' por nonces/hashes, remova 'unsafe-eval' e liste origens explícitas.", ()),
    Vuln("missing-frame-protection", "Proteção contra clickjacking ausente", "medium", 1021, A05, 4.3,
         "A página pode ser embutida em frames de outros sites, permitindo ataques de clickjacking.",
         "Envie `Content-Security-Policy: frame-ancestors 'none'` (ou 'self') e, para navegadores "
         "antigos, `X-Frame-Options: DENY`.", ()),
    Vuln("missing-xcto", "X-Content-Type-Options ausente", "low", 693, A05, 3.1,
         "Sem `nosniff`, o navegador pode interpretar arquivos com um tipo diferente do declarado.",
         "Envie `X-Content-Type-Options: nosniff` em todas as respostas.", ()),
    Vuln("missing-referrer-policy", "Referrer-Policy ausente", "info", 200, A05, 0.0,
         "Sem Referrer-Policy, URLs completas podem vazar para sites de terceiros.",
         "Envie `Referrer-Policy: strict-origin-when-cross-origin` ou mais restritiva.", ()),
    Vuln("missing-permissions-policy", "Permissions-Policy ausente", "info", 693, A05, 0.0,
         "A página não restringe o uso de recursos do navegador (câmera, microfone, geolocalização).",
         "Defina uma Permissions-Policy desabilitando os recursos que a aplicação não usa.", ()),
    # ---- Cookies ----------------------------------------------------------
    Vuln("cookie-no-secure", "Cookie sem o atributo Secure", "medium", 614, A05, 4.3,
         "O cookie pode ser enviado por conexões HTTP sem criptografia.",
         "Defina o atributo Secure em todos os cookies, especialmente os de sessão.", ()),
    Vuln("cookie-no-httponly", "Cookie sem o atributo HttpOnly", "medium", 1004, A05, 4.3,
         "O cookie é acessível via JavaScript e pode ser roubado em caso de XSS.",
         "Defina HttpOnly em cookies de sessão e autenticação.", ()),
    Vuln("cookie-no-samesite", "Cookie sem o atributo SameSite", "low", 1275, A01, 3.1,
         "Sem SameSite explícito, o cookie pode ser enviado em requisições entre sites (CSRF).",
         "Defina `SameSite=Lax` ou `SameSite=Strict`.", ()),
    # ---- Transport --------------------------------------------------------
    Vuln("no-https", "Site servido sem HTTPS", "high", 319, A02, 7.4,
         "O alvo é servido por HTTP sem criptografia; credenciais e dados podem ser interceptados e "
         "alterados em trânsito.",
         "Sirva todo o site por HTTPS com certificado válido e redirecione HTTP para HTTPS.", ()),
    Vuln("no-https-redirect", "HTTP não redireciona para HTTPS", "medium", 319, A02, 4.8,
         "A versão HTTP do site responde sem redirecionar para HTTPS.",
         "Configure redirecionamento permanente (301) de HTTP para HTTPS e habilite HSTS.", ()),
    Vuln("tls-cert-expired", "Certificado TLS expirado", "high", 298, A02, 7.4,
         "O certificado TLS do servidor está expirado.",
         "Renove o certificado e automatize a renovação (por exemplo, com ACME).", ()),
    Vuln("tls-cert-expiring", "Certificado TLS próximo do vencimento", "low", 298, A02, 2.6,
         "O certificado TLS vence em menos de 30 dias.",
         "Renove o certificado e automatize a renovação.", ()),
    Vuln("tls-cert-invalid", "Certificado TLS inválido ou não confiável", "high", 295, A02, 7.4,
         "O certificado não pôde ser validado (cadeia não confiável, autoassinado ou nome divergente).",
         "Instale um certificado emitido por autoridade confiável, com a cadeia completa e o nome "
         "correto.", ()),
    Vuln("tls-legacy-protocol", "Protocolo TLS obsoleto habilitado", "medium", 326, A02, 5.9,
         "O servidor aceita TLS 1.0 ou 1.1, protocolos obsoletos com fraquezas conhecidas.",
         "Desabilite TLS 1.0 e 1.1; aceite apenas TLS 1.2 e 1.3.", ()),
    Vuln("mixed-content", "Conteúdo misto (recursos HTTP em página HTTPS)", "medium", 319, A02, 4.8,
         "A página HTTPS carrega scripts ou outros recursos ativos por HTTP, que podem ser adulterados.",
         "Carregue todos os recursos por HTTPS.", ()),
    Vuln("password-over-http", "Formulário de senha enviado por HTTP", "high", 319, A02, 7.4,
         "Um formulário com campo de senha está em página HTTP ou envia para destino HTTP.",
         "Sirva e envie formulários de autenticação exclusivamente por HTTPS.", ()),
    # ---- Misc -------------------------------------------------------------
    Vuln("cors-reflect-credentials", "CORS reflete origem arbitrária com credenciais", "high", 942, A05, 8.1,
         "O servidor reflete qualquer Origin em Access-Control-Allow-Origin e permite credenciais, "
         "permitindo que sites maliciosos leiam respostas autenticadas.",
         "Valide a origem contra uma lista de permissão fixa e nunca combine reflexão de origem com "
         "Access-Control-Allow-Credentials: true.",
         ("https://portswigger.net/web-security/cors",)),
    Vuln("cors-reflect", "CORS reflete origem arbitrária", "low", 942, A05, 3.7,
         "O servidor reflete qualquer Origin em Access-Control-Allow-Origin (sem credenciais).",
         "Valide a origem contra uma lista de permissão fixa.", ()),
    Vuln("cors-null-origin", "CORS aceita origem 'null' com credenciais", "medium", 942, A05, 6.5,
         "A origem 'null' é aceita com credenciais; ela pode ser forjada com iframes em sandbox.",
         "Não inclua 'null' na lista de origens permitidas.", ()),
    Vuln("trace-enabled", "Método HTTP TRACE habilitado", "low", 16, A05, 3.1,
         "O servidor responde ao método TRACE ecoando a requisição.",
         "Desabilite o método TRACE no servidor web.", ()),
    Vuln("csrf-token-missing", "Formulário POST sem token anti-CSRF aparente", "low", 352, A01, 4.3,
         "O formulário altera estado via POST e não contém campo oculto com token anti-CSRF. "
         "Verificação heurística: confirme manualmente se há outra defesa (SameSite, cabeçalho customizado).",
         "Inclua tokens anti-CSRF por sessão em todos os formulários que alteram estado e defina "
         "SameSite nos cookies de sessão.",
         ("https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",)),
    Vuln("sri-missing", "Script externo sem Subresource Integrity", "low", 353, A08, 3.1,
         "Scripts carregados de outros domínios sem o atributo integrity podem ser adulterados se o "
         "terceiro for comprometido.",
         "Adicione os atributos `integrity` e `crossorigin` aos scripts de terceiros ou hospede-os "
         "localmente.", ()),
    Vuln("vulnerable-js-library", "Biblioteca JavaScript com vulnerabilidade conhecida", "medium", 1104, A06, 6.1,
         "A página carrega uma versão de biblioteca JavaScript com vulnerabilidades publicadas.",
         "Atualize a biblioteca para a versão corrigida mais recente.", ()),
    Vuln("security-txt-missing", "security.txt ausente", "info", None, A05, 0.0,
         "O site não publica /.well-known/security.txt, dificultando o contato de pesquisadores.",
         "Publique um security.txt com contato e política de divulgação (RFC 9116).",
         ("https://securitytxt.org/",)),
    Vuln("windows-api-arbitrary-file-read",
         "Leitura arbitrária de arquivos via API Windows (CWE-22)", "critical", 22, A01, 9.1,
         "Uma API JSON no servidor IIS/ASP.NET retorna o conteúdo de qualquer arquivo do sistema "
         "informado como caminho absoluto. Arquivos de configuração protegidos por blocklist de nome "
         "exato (ex.: 'web.config') podem ser lidos com a adição de um ponto final ('web.config.'), "
         "pois o Win32 CreateFile() ignora pontos finais ao abrir o arquivo.",
         "Restrinja as APIs de leitura de arquivo a caminhos permitidos por lista (allowlist) "
         "baseada em diretório, nunca por nome. Remova ou proteja com autenticação qualquer endpoint "
         "que aceite caminho absoluto como parâmetro.",
         ("https://cwe.mitre.org/data/definitions/22.html",
          "https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file")),
]

CATALOG: dict[str, Vuln] = {v.id: v for v in _ITEMS}


def get(check_id: str) -> Vuln:
    return CATALOG[check_id]
