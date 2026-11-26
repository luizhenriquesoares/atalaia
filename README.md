# Atalaia

Plataforma SaaS de varredura de vulnerabilidades em aplicações web (DAST), multi-tenant, feita para
times de segurança avaliarem **apenas alvos cuja propriedade foi comprovada**.

O conhecimento ofensivo está a serviço da defesa: as verificações detectam a falha e explicam como
corrigir, sem explorar, extrair dados ou alterar o alvo.

## O que já faz

| Área | Capacidade |
| --- | --- |
| Autorização | Varredura bloqueada até a comprovação de propriedade (DNS TXT, arquivo em `/.well-known/` ou meta tag). A prova expira em 90 dias e é revalidada na fila e na execução. |
| Proteção contra abuso | Bloqueio de alvos internos (loopback, redes privadas, link-local, metadados de nuvem), conexão fixada no IP validado (anti DNS rebinding), escopo restrito à origem do alvo, limite de requisições por segundo e orçamento por varredura. |
| Motor | Crawler assíncrono de mesma origem (links, formulários, `robots.txt`, `sitemap.xml`) que nunca segue links de logout ou exclusão, mais um navegador real (Chromium) que renderiza JavaScript, navega em aplicações de página única e descobre as chamadas de API que a página faz. |
| Prova, não suposição | XSS é confirmado por execução: a página é aberta no navegador com uma carga que chama uma função que só o scanner define. Se a função roda, o achado sai como "Comprovado". O mesmo teste encontra XSS baseado em DOM (parâmetros e fragmento da URL) que o servidor nem chega a refletir. |
| Detecção | 51 tipos de achado: SQL injection (erro e booleana), XSS refletido, armazenado e baseado em DOM, SSTI, path traversal, redirecionamento aberto, injeção de CRLF, envenenamento por cabeçalho Host, JWT inseguro (`alg: none` e segredos fracos), sessão na URL, CORS inseguro, arquivos sensíveis expostos (`.git`, `.env`, backups, chaves), endpoints de depuração, introspecção GraphQL, segredos em respostas, TLS (certificado e protocolos obsoletos), cabeçalhos de segurança, cookies, CSRF, conteúdo misto, SRI e bibliotecas JavaScript vulneráveis. Parâmetros de APIs JSON também são testados. |
| Gestão | Achados deduplicados entre varreduras, com histórico, correção automática quando deixam de ser detectados, reabertura em regressão e triagem (falso positivo e risco aceito, com justificativa). |
| Classificação | Severidade, CVSS, CWE e categoria OWASP Top 10 2021, com evidência e orientação de correção em português. |
| Relatórios | HTML (para impressão/PDF), CSV, JSON e SARIF 2.1.0 para integração com pipelines. |
| Plataforma | Organizações isoladas, quatro papéis (proprietário, administrador, analista, leitor), chaves de API, varreduras agendadas e varredura autenticada com credenciais criptografadas. |
| Acesso | Verificação em duas etapas (TOTP, compatível com Google/Microsoft Authenticator, Authy, 1Password), códigos de recuperação de uso único, política que torna o segundo fator obrigatório para a organização e redefinição por administrador. |
| Escala | Fila de varreduras no banco de dados: qualquer quantidade de workers (`python -m atalaia.worker`) disputa os trabalhos com reivindicação atômica, envia heartbeat e tem as varreduras recuperadas se o processo morrer. Cancelamento e duração máxima funcionam entre processos. |
| Assistentes de IA | Servidor MCP (`atalaia-mcp`) com 19 ferramentas: o Claude ou outro assistente consulta o painel, cadastra e verifica alvos, dispara e acompanha varreduras, compara resultados, tria achados e gera relatórios, sempre pela API e sob as mesmas regras. |
| Auditoria | Trilha encadeada por hash (qualquer adulteração é detectada) de logins, verificações, varreduras, recusas, triagens e exportações. |

### Perfis de varredura

- **Passiva**: navega como um visitante e analisa as respostas. Não envia nenhuma carga de teste.
- **Padrão**: adiciona verificações do servidor e testes em parâmetros de leitura (GET).
- **Completa**: inclui formulários POST, exceto os que parecem alterar dados críticos (exclusão,
  pagamento, senha, cadastro, upload) e os que têm campo de senha.

Nenhum perfil usa consultas empilhadas, escrita, execução de comandos, cargas de atraso ou força bruta.

### Navegador isolado

Quando o Chromium está disponível, ele entra em todos os perfis para renderizar as páginas. Ao
renderizar, a página faz as requisições que faria para qualquer visitante (inclusive as chamadas de API
do próprio JavaScript); cargas de teste só são enviadas nos perfis Padrão e Completa.

O navegador nunca fala com a rede por conta própria. Ele é iniciado atrás de um proxy inexistente e
cada requisição é interceptada: as do alvo passam pelo mesmo cliente com escopo, limite de taxa,
orçamento e IP fixado usado pelo resto da varredura; scripts e estilos de terceiros são buscados pelo
servidor apenas em endereços públicos; todo o resto (outras origens, WebSocket, redes internas) é
bloqueado. Assim, uma página maliciosa no alvo não consegue usar o scanner para alcançar a rede interna.

## Demonstração local em um comando

```bash
./scripts/run-demo.sh
```

O script cria um ambiente virtual, instala as dependências e sobe duas coisas em `127.0.0.1`: o Atalaia
na porta 8000 e uma loja deliberadamente vulnerável na porta 8901. Ele cria a conta de demonstração,
comprova a propriedade do alvo local e já dispara a primeira varredura. Abra http://127.0.0.1:8000 e
entre com `demo@atalaia.local` e a senha `Atalaia-Demo-Local-2026`. Requer Python 3.11 ou mais novo.

Na primeira execução o script também baixa o Chromium (cerca de 150 MB) para a renderização de
JavaScript e a prova de XSS. Para pular essa etapa: `ATALAIA_DEMO_BROWSER=off ./scripts/run-demo.sh`.

## Como rodar

```bash
pip install -e ".[dev,browser]"
python -m playwright install chromium          # opcional: sem ele a varredura segue sem JavaScript
export ATALAIA_SECRET_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(48))')"
uvicorn atalaia.main:app --port 8000
# painel em http://localhost:8000
```

Com Docker e PostgreSQL (uma API e workers separados; aumente os workers com `--scale`):

```bash
export POSTGRES_PASSWORD=... ATALAIA_SECRET_KEY=...   # 32+ caracteres
docker compose up --build --scale worker=2
```

### API e workers em processos separados

Por padrão o processo da API também executa as varreduras, o que basta para uma instalação pequena.
Para escalar, defina `ATALAIA_EMBEDDED_WORKER=false` na API e rode `python -m atalaia.worker` em quantas
máquinas quiser, todas apontando para o mesmo banco e com a mesma `ATALAIA_SECRET_KEY`. Cada worker
executa até `ATALAIA_SCAN_WORKERS` varreduras ao mesmo tempo. Use PostgreSQL nesse modo.

Ao iniciar, API e workers criam as tabelas que faltam e adicionam as colunas novas de uma versão mais
recente. Mudanças que não sejam aditivas ainda exigem migração manual.

### Testes

Sobem uma aplicação vulnerável e uma aplicação segura em 127.0.0.1 e varrem as duas, inclusive com o
navegador (os testes de navegador são pulados se o Playwright não estiver instalado):

```bash
pytest
# a mesma suíte contra PostgreSQL (o schema "public" desse banco é apagado a cada teste):
ATALAIA_TEST_DATABASE_URL=postgresql+psycopg://usuario:senha@localhost/atalaia_test pytest
```

### Configuração

| Variável | Padrão | Descrição |
| --- | --- | --- |
| `ATALAIA_SECRET_KEY` | aleatória por processo | Assina sessões e deriva a chave que criptografa credenciais de varredura. Obrigatória em produção. |
| `ATALAIA_DATABASE_URL` | `sqlite:///./atalaia.db` | URL SQLAlchemy. |
| `ATALAIA_ALLOW_PRIVATE_TARGETS` | `false` | Permite alvos em redes internas. Só para instalações on-premises. |
| `ATALAIA_ALLOW_REGISTRATION` | `true` | Cadastro aberto de novas organizações. |
| `ATALAIA_VERIFICATION_TTL_DAYS` | `90` | Validade da prova de propriedade. |
| `ATALAIA_DEFAULT_RPS` / `ATALAIA_MAX_RPS` | `8` / `20` | Limite de requisições por segundo por alvo. |
| `ATALAIA_MAX_PAGES` / `ATALAIA_MAX_REQUESTS` | `150` / `6000` | Orçamento por varredura. |
| `ATALAIA_MAX_SCANS_PER_ORG` | `3` | Varreduras simultâneas por organização. |
| `ATALAIA_BROWSER` | `auto` | `auto` usa o Chromium quando instalado; `off` desliga a renderização de JavaScript. |
| `ATALAIA_BROWSER_MAX_PAGES` | `25` | Páginas renderizadas por varredura. |
| `ATALAIA_BROWSER_THIRD_PARTY` | `true` | Busca scripts e estilos de terceiros (somente em endereços públicos) para a página renderizar por completo. |
| `ATALAIA_BROWSER_SANDBOX` | `false` | Liga o sandbox do Chromium. Exige um host que permita user namespaces; em contêiner o isolamento vem do próprio contêiner. |
| `ATALAIA_EMBEDDED_WORKER` | `true` | A API também executa varreduras. Use `false` quando houver workers dedicados. |
| `ATALAIA_SCAN_WORKERS` | `4` | Varreduras simultâneas por processo worker. |
| `ATALAIA_MAX_SCAN_SECONDS` | `7200` | Duração máxima de uma varredura. |
| `ATALAIA_WORKER_STALE` | `90` | Segundos sem heartbeat até a varredura de um worker ser dada como perdida. |
| `ATALAIA_MCP` | `true` | Servidor MCP embutido em `/mcp` (requer o extra `[mcp]`). |
| `ATALAIA_PUBLIC_URL` | deduzido da requisição | Endereço público, usado como emissor OAuth e nos metadados do MCP. |
| `ATALAIA_OAUTH_ACCESS_TTL` / `ATALAIA_OAUTH_REFRESH_DAYS` | `3600` / `30` | Validade dos tokens do conector MCP. |
| `ATALAIA_TOKEN_TTL` | `28800` | Duração da sessão, em segundos. |

## API

Todas as rotas ficam em `/api/v1` e a especificação em `/api/openapi.json`. Autenticação por
`Authorization: Bearer <token>` ou `X-API-Key: atl_...`.

```bash
# No pipeline: iniciar uma varredura e baixar o resultado em SARIF
curl -X POST "$ATALAIA/api/v1/scans" -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
     -d '{"target_id": "'$TARGET'", "profile": "standard"}'
curl "$ATALAIA/api/v1/scans/$SCAN/report?format=sarif" -H "X-API-Key: $KEY" -o atalaia.sarif
```

## Servidor MCP (assistentes de IA)

O `atalaia-mcp` expõe o Atalaia pelo [Model Context Protocol](https://modelcontextprotocol.io), para que
o Claude (Desktop, Code) ou qualquer cliente MCP opere a plataforma em linguagem natural: "varra a loja
com o perfil padrão e me explique os achados críticos", "compare com a varredura de ontem", "faça um
resumo executivo para a diretoria".

O servidor é só um cliente da API autenticado por chave. Ele não toca no banco nem no motor, então não há
como contornar nada: a comprovação de propriedade, o bloqueio de alvos internos, os limites por
organização, o papel da chave e a trilha de auditoria valem exatamente como na API. Cada ação do
assistente aparece na auditoria atribuída à chave.

```bash
pip install -e ".[mcp]"
# Crie uma chave em Equipe e chaves > Chaves de API. Papel "leitor" para só consultar, "analista" para varrer e triar.
```

Configuração no Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "atalaia": {
      "command": "atalaia-mcp",
      "env": { "ATALAIA_URL": "https://atalaia.suaempresa.com", "ATALAIA_API_KEY": "atl_..." }
    }
  }
}
```

No Claude Code: `claude mcp add atalaia -e ATALAIA_URL=https://... -e ATALAIA_API_KEY=atl_... -- atalaia-mcp`.

### Uso remoto: o MCP embutido em `/mcp`

O próprio servidor do Atalaia também atende MCP em `https://<seu-atalaia>/mcp` (streamable HTTP), sem
instalar nada na máquina do usuário. Cada cliente se autentica com a **própria** chave de API em
`Authorization: Bearer atl_...`; sem chave válida a resposta é 401 e nem a lista de ferramentas aparece.
O servidor não guarda chave nenhuma: cada ação roda com o papel e a organização da chave de quem chamou,
então várias organizações podem usar o mesmo endpoint isoladas umas das outras, e a auditoria registra a
chave e o IP de quem fez a ação.

```bash
claude mcp add --transport http atalaia https://atalaia.suaempresa.com/mcp \
  --header "Authorization: Bearer atl_..."
```

O endpoint não guarda sessão entre requisições, então funciona com várias réplicas da API atrás de um
balanceador. Desligue com `ATALAIA_MCP=false`. Ele só existe quando o extra `[mcp]` está instalado (a
imagem Docker já inclui).

### Conector no claude.ai (OAuth 2.1)

No claude.ai, em Configurações > Conectores > Adicionar conector personalizado, informe
`https://<seu-atalaia>/mcp`. O claude.ai descobre o login sozinho e abre a tela do Atalaia, onde a pessoa
entra com e-mail, senha e segundo fator e escolhe o que o assistente poderá fazer: **somente consultar**
(papel leitor) ou **consultar e agir** (papel analista; só para quem tem esse papel). Nunca mais do que
analista: gestão de usuários e chaves fica fora do alcance do conector. Os aplicativos conectados aparecem
em Minha conta (administradores veem os da organização) e podem ser desconectados na hora.

O servidor de autorização segue a especificação de autorização do MCP: metadados do recurso protegido
(RFC 9728) e do servidor (RFC 8414), registro dinâmico de cliente (RFC 7591), PKCE S256 obrigatório,
indicador de recurso (RFC 8707), `iss` na resposta (RFC 9207) e revogação (RFC 7009). Os tokens são opacos
e guardados só como hash; o de acesso vale 1 hora e o de renovação 30 dias, com rotação a cada uso.
Reapresentar um token de renovação ou um código já usado revoga a conexão inteira. Trocar a senha, mudar o
papel ou desativar o usuário desconecta todos os aplicativos dele.

Em produção defina `ATALAIA_PUBLIC_URL` (por exemplo `https://atalaia.suaempresa.com`): é o emissor
anunciado nos metadados e o endereço que o claude.ai precisa alcançar pela internet.

Para apontar um MCP remoto para um Atalaia em outro lugar, há também o modo avulso:
`ATALAIA_URL=https://... atalaia-mcp --transport streamable-http --port 8765` (mesma autenticação por
chave do cliente; sirva atrás de HTTPS).

| Ferramenta | O que faz |
| --- | --- |
| `get_dashboard`, `whoami` | Nota de segurança, achados por severidade e OWASP, varreduras recentes; organização e papel da chave. |
| `list_targets`, `get_target` | Alvos com status de verificação e instruções de comprovação de propriedade. |
| `create_target`, `verify_target_ownership`, `schedule_target` | Cadastro, conferência da prova publicada pelo dono e agenda diária/semanal. |
| `start_scan`, `get_scan`, `list_scans`, `cancel_scan` | Ciclo de vida das varreduras (recusadas se o alvo não estiver verificado). |
| `wait_for_scan` | Acompanha a varredura com notificações de progresso e devolve os achados mais graves ao terminar. |
| `compare_scans` | Achados novos, que sumiram e que persistem entre duas varreduras (validar correção, achar regressão). |
| `list_findings`, `get_finding`, `triage_finding` | Busca com filtros, detalhes com correção e referências, triagem com justificativa obrigatória. |
| `get_scan_report` | Relatório em Markdown (para conversar), SARIF, CSV ou JSON. |
| `list_checks`, `get_check` | Catálogo do que o Atalaia detecta: severidade, CWE, OWASP, perfis que rodam cada verificação, descrição e correção. |

Também há três roteiros prontos (prompts MCP): `assess_site` (avaliar um site do começo ao fim),
`executive_summary` e `validate_fix`.

Proteções do próprio servidor MCP:

- Recusa mandar a chave por `http://` para fora de localhost (use https, ou
  `ATALAIA_MCP_ALLOW_INSECURE_HTTP=true` por sua conta).
- Ids são validados antes de entrar na URL ou no corpo, então o assistente não consegue desviar a chave para outra rota.
- Evidências vêm marcadas como `untrusted_content_from_target` e truncadas: o texto vem do site varrido e
  pode conter tentativas de injeção de prompt contra o assistente.
- `--read-only` (ou `ATALAIA_MCP_READ_ONLY=true`) registra apenas as ferramentas de consulta.
- No modo HTTP só chaves de API são aceitas (tokens de sessão do painel não), e uma chave revogada para de
  funcionar na hora em qualquer ação.

Funciona com o SDK MCP para Python 1.x (1.10 ou mais novo) e 2.x.

## Arquitetura

```
atalaia/
  api/app.py        API FastAPI, RBAC, isolamento por organização, cabeçalhos de segurança
  scans.py          portão de autorização, fila no banco, ciclo de vida dos achados, agenda
  worker.py         processo dedicado de execução de varreduras
  mfa.py            segundo fator (TOTP) e códigos de recuperação
  ownership.py      comprovação de propriedade
  netguard.py       bloqueio de alvos internos e fixação de IP
  audit.py          trilha de auditoria encadeada por hash
  reports.py        HTML, CSV, JSON e SARIF
  mcp_server.py     servidor MCP para assistentes de IA (cliente da API)
  oauth.py          servidor de autorização OAuth 2.1 do conector MCP
  scanner/
    http.py         cliente com escopo, limite de taxa, orçamento e cancelamento
    crawler.py      descoberta de páginas e pontos de entrada
    passive.py      verificações sobre respostas já obtidas
    active.py       sondas não destrutivas
    browser.py      Chromium isolado: renderização, captura de APIs e prova de XSS
    knowledge.py    catálogo: severidade, CWE, OWASP, descrição e correção
  web/              painel (JavaScript puro, compatível com CSP estrita)
```

## Limites conhecidos

Para ser transparente sobre a distância até os líderes do mercado:

- Não há gravação de sequência de login; a varredura autenticada usa cabeçalhos de sessão fornecidos.
- Não há detecção fora de banda, então falhas cegas (SSRF cego, XXE cego, SQL injection cega por tempo)
  não são encontradas.
- São 51 tipos de achado; scanners comerciais maduros têm milhares, incluindo CVEs de produtos específicos.
- O navegador renderiza até 25 páginas por varredura e não preenche formulários nem clica em botões:
  telas que só aparecem depois de uma interação ficam de fora.
- Os limites de tentativa de login ficam na memória de cada processo da API; com várias réplicas da API
  o limite efetivo é multiplicado pelo número de réplicas.
- A atualização de banco é só aditiva (tabelas e colunas novas). Não há ferramenta de migração.
- Faltam SSO (SAML/OIDC), cobrança e notificações (e-mail, Slack, Jira). O login do conector MCP usa
  e-mail e senha do Atalaia; ainda não delega a um provedor de identidade corporativo.
- A suíte automatizada roda contra SQLite e PostgreSQL 16, sempre com alvos locais. O produto ainda não
  foi exercitado contra sites reais na internet nem passou por teste de carga ou auditoria externa.

## Uso responsável

Varrer sistemas sem autorização é ilegal em muitas jurisdições. A plataforma exige a prova de
propriedade, mas a responsabilidade pelo uso é da organização cliente.
