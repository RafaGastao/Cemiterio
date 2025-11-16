/* app.js - Minimal API-first SPA
 * - Stores only session token in localStorage (cem_token)
 * - Frontend talks to backend via API_BASE
 */

const API_BASE = 'https://cemiterio-0elv.onrender.com/api';

let token = localStorage.getItem('cem_access_token') || null;
let currentUser = null; // populated after successful login

// --- MÓDULO DE CRIPTOGRAFIA ---
const cryptoModule = (() => {
    let serverPublicKey = null;
    let clientKeyPair = null;

    // Função para importar a chave pública do servidor (formato PEM)
    async function importServerKey(pem) {
        const pemHeader = "-----BEGIN PUBLIC KEY-----";
        const pemFooter = "-----END PUBLIC KEY-----";
        const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length).replace(/\s/g, '');
        const binaryDer = window.atob(pemContents);
        const binaryDerArr = new Uint8Array(binaryDer.length).map((_, i) => binaryDer.charCodeAt(i));
        
        return window.crypto.subtle.importKey(
            "spki",
            binaryDerArr.buffer,
            { name: "RSA-OAEP", hash: "SHA-256" },
            true,
            ["encrypt"]
        );
    }

    // Gera o par de chaves do cliente
    async function generateClientKeys() {
        clientKeyPair = await window.crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256",
            },
            true,
            ["encrypt", "decrypt"]
        );
    }

    // Exporta a chave pública do cliente para o formato PEM para enviar ao servidor
    async function exportClientPublicKey() {
        if (!clientKeyPair) return null;
        const spki = await window.crypto.subtle.exportKey("spki", clientKeyPair.publicKey);
        const spkiB64 = window.btoa(String.fromCharCode(...new Uint8Array(spki)));
        return `-----BEGIN PUBLIC KEY-----\n${spkiB64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
    }

    return {
        // Inicializa o módulo: busca a chave do servidor e gera as do cliente
        initialize: async () => {
            try {
                const res = await fetch(API_BASE + '/security/public-key');
                if (!res.ok) throw new Error('Failed to fetch server public key');
                const { public_key } = await res.json();
                serverPublicKey = await importServerKey(public_key);
                await generateClientKeys();
                console.log("Crypto module initialized.");
            } catch (e) {
                console.error("Crypto initialization failed:", e);
                throw e;
            }
        },
        // Registra a chave pública do cliente no servidor
        registerKeyWithServer: async () => {
            if (!clientKeyPair) throw new Error("Client keys not generated.");
            const publicKeyPEM = await exportClientPublicKey();
            await api('security/register-key', {
                method: 'POST',
                body: JSON.stringify({ public_key: publicKeyPEM }),
                skipEncryption: true // Flag para não criptografar esta requisição específica
            });
            console.log("Client public key registered with server.");
        },
        // Criptografa um payload para enviar ao servidor
        encrypt: async (data) => {
            if (!serverPublicKey) throw new Error("Server public key not available.");
            
            // 1. Gerar chave de sessão e IV com Web Crypto API (mais seguro para geração)
            const sessionKey = await window.crypto.subtle.generateKey({ name: "AES-CBC", length: 256 }, true, ["encrypt", "decrypt"]);
            const iv = window.crypto.getRandomValues(new Uint8Array(16));

            // 2. Exportar a chave de sessão para usar com CryptoJS
            const rawSessionKey = await window.crypto.subtle.exportKey("raw", sessionKey);
            const sessionKeyHex = CryptoJS.lib.WordArray.create(rawSessionKey);
            const ivHex = CryptoJS.lib.WordArray.create(iv);

            // 3. Criptografar a chave de sessão com RSA (Web Crypto API)
            const encryptedKey = await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, serverPublicKey, rawSessionKey);
            
            // 4. Criptografar os dados com CryptoJS (AES-CBC)
            const dataStr = JSON.stringify(data);
            const encryptedData = CryptoJS.AES.encrypt(dataStr, sessionKeyHex, { 
                iv: ivHex, 
                mode: CryptoJS.mode.CBC, 
                padding: CryptoJS.pad.Pkcs7 
            });

            return {
                encrypted_key: btoa(String.fromCharCode(...new Uint8Array(encryptedKey))),
                iv: btoa(String.fromCharCode(...iv)),
                data: encryptedData.toString() // CryptoJS já usa Base64 por padrão
            };
        },
        // Decriptografa um payload recebido do servidor
        decrypt: async (encryptedPayload) => {
            if (!clientKeyPair) throw new Error("Client keys not available.");

            // 1. Decodificar dados recebidos
            const encryptedKey = Uint8Array.from(atob(encryptedPayload.encrypted_key), c => c.charCodeAt(0));
            const iv = Uint8Array.from(atob(encryptedPayload.iv), c => c.charCodeAt(0));
            const data = encryptedPayload.data; // Já está em Base64

            // 2. Decriptografar a chave de sessão com RSA (Web Crypto API)
            const sessionKeyData = await window.crypto.subtle.decrypt({ name: "RSA-OAEP" }, clientKeyPair.privateKey, encryptedKey);
            
            // 3. Preparar chave e IV para CryptoJS
            const sessionKeyHex = CryptoJS.lib.WordArray.create(sessionKeyData);
            const ivHex = CryptoJS.lib.WordArray.create(iv);

            // 4. Decriptografar os dados com CryptoJS (AES-CBC)
            const decrypted = CryptoJS.AES.decrypt(data, sessionKeyHex, { 
                iv: ivHex, 
                mode: CryptoJS.mode.CBC, 
                padding: CryptoJS.pad.Pkcs7 
            });
            
            const decryptedStr = decrypted.toString(CryptoJS.enc.Utf8);
            if (!decryptedStr) {
                throw new Error("Decryption resulted in empty string. Check for padding or key errors.");
            }
            
            return JSON.parse(decryptedStr);
        }
    };
})();


function authHeaders(){ return token ? { 'Authorization': 'Bearer ' + token } : {}; }

// --- FUNÇÃO API ATUALIZADA PARA REFRESH TOKEN ---
let isRefreshing = false;
let failedQueue = [];

/**
 * Processa uma fila de requisições que falharam devido a um token expirado.
 * @param {Error|null} error - Um erro, se a renovação do token falhou.
 * @param {string|null} token - O novo token de acesso.
 */
const processQueue = (error, token = null) => {
    failedQueue.forEach(prom => {
        if (error) {
            prom.reject(error);
        } else {
            prom.resolve(token);
        }
    });
    failedQueue = [];
};

/**
 * Função central para fazer requisições à API.
 * Lida com autenticação, criptografia, e renovação de token (refresh token).
 * @param {string} path - O caminho do endpoint da API (ex: 'usuarios').
 * @param {object} opts - Opções para a função fetch (method, body, headers, etc).
 * @returns {Promise<any>} - A resposta da API em formato JSON.
 */
async function api(path, opts = {}){
    opts.headers = Object.assign({'Content-Type':'application/json'}, authHeaders(), opts.headers || {});
    
    // --- LÓGICA DE CRIPTOGRAFIA ---
    const shouldEncrypt = opts.method === 'POST' || opts.method === 'PUT';
    // Não criptografa se o corpo não existir ou se a flag 'skipEncryption' estiver presente
    if (shouldEncrypt && opts.body && !opts.skipEncryption) {
        try {
            const encryptedBody = await cryptoModule.encrypt(JSON.parse(opts.body));
            opts.body = JSON.stringify(encryptedBody);
        } catch (e) {
            console.error("Encryption failed:", e);
            return Promise.reject(new Error("Falha ao criptografar a requisição."));
        }
    }
    delete opts.skipEncryption; // Limpa a flag
    // --- FIM DA LÓGICA DE CRIPTOGRAFIA ---

    const originalRequest = async () => fetch(API_BASE + '/' + path, opts);

    let res = await originalRequest();

    if (res.status === 401) {
        if (isRefreshing) {
            return new Promise((resolve, reject) => {
                failedQueue.push({ resolve, reject });
            })
            .then(newToken => {
                opts.headers['Authorization'] = 'Bearer ' + newToken;
                return originalRequest();
            })
            .then(r => r.json());
        }

        isRefreshing = true;
        const refreshToken = localStorage.getItem('cem_refresh_token');
        if (!refreshToken) {
            logoutUser();
            return Promise.reject(new Error('Sessão expirada.'));
        }

        try {
            const refreshRes = await fetch(API_BASE + '/token/refresh', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ refresh_token: refreshToken })
            });

            if (!refreshRes.ok) throw new Error('Não foi possível renovar a sessão.');

            const { access_token } = await refreshRes.json();
            token = access_token;
            localStorage.setItem('cem_access_token', access_token);
            opts.headers['Authorization'] = 'Bearer ' + access_token;
            
            processQueue(null, access_token);
            res = await originalRequest(); // Tenta a requisição original novamente

        } catch (e) {
            processQueue(e, null);
            logoutUser();
            return Promise.reject(e);
        } finally {
            isRefreshing = false;
        }
    }

    if(res.status === 204) return null;
    let j = await res.json().catch(()=>null);

    // --- LÓGICA DE DECRIPTOGRAFIA ---
    // Descriptografa se a resposta contiver uma chave criptografada, independentemente do método.
    if (j && j.encrypted_key) {
        try {
            j = await cryptoModule.decrypt(j);
        } catch (e) {
            console.error("Decryption failed:", e);
            return Promise.reject(new Error("Falha ao decriptografar a resposta do servidor."));
        }
    }
    // --- FIM DA LÓGICA DE DECRIPTOGRAFIA ---

    if(!res.ok) throw new Error((j && j.error) ? j.error : ('HTTP ' + res.status));
    return j;
}

/**
 * Desloga o usuário, limpando tokens e estado local.
 * Tenta invalidar o token no backend.
 */
function logoutUser() {
    api('logout', { method: 'POST', skipEncryption: true }).catch(err => console.error("Logout API call failed:", err)); // Tenta invalidar o token no backend
    token = null;
    currentUser = null;
    localStorage.removeItem('cem_access_token');
    localStorage.removeItem('cem_refresh_token');
    location.hash = '#login';
    render();
}

/**
 * Verifica se há um usuário logado.
 * @returns {boolean} - True se o usuário estiver logado.
 */
function isUserLoggedIn() {
    return currentUser !== null;
}

/**
 * Verifica se o usuário logado é um administrador.
 * @returns {boolean} - True se o usuário for admin.
 */
function isAdmin() {
    return currentUser && currentUser.role === 'admin';
}

// API helpers (Original)
/** Faz o login do usuário. */
const login = (username, password) => api('login', { method: 'POST', body: JSON.stringify({ username, password }), skipEncryption: true });
/** Solicita um token de recuperação de senha. */
const forgotPassword = (email, username) => api('forgot-password', { method: 'POST', body: JSON.stringify({ email, username }), skipEncryption: true });
/** Reseta a senha usando um token. */
const resetPassword = (token, password) => api(`reset-password/${token}`, { method: 'POST', body: JSON.stringify({ password }), skipEncryption: true });
/** Busca o catálogo de produtos. */
const getCatalog = () => api('catalogo');
/**
 * Busca os itens do carrinho de um usuário.
 * @param {number|null} userId - O ID do usuário.
 */
const getCart = (userId = null) => {
    const url = new URL(API_BASE + '/carrinho');
    if(userId) url.searchParams.append('user_id', userId);
    return fetch(url.toString(), { headers: authHeaders() }).then(r => r.ok ? r.json() : Promise.reject(new Error('Erro ao buscar carrinho')));
};
/** Adiciona um item ao carrinho. */
const addCartItem = (produto_id, quantidade=1, user_id=null) => api('carrinho', { method: 'POST', body: JSON.stringify({ produto_id, quantidade, user_id }) });
/** Atualiza a quantidade de um item no carrinho. */
const updateCartItem = (id, quantidade) => api('carrinho/' + id, { method: 'PUT', body: JSON.stringify({ quantidade }) });
/** Remove um item do carrinho. */
const removeCartItem = (id) => fetch(API_BASE + '/carrinho/' + id, { method: 'DELETE', headers: authHeaders() }).then(r => r.ok ? r.json() : Promise.reject(new Error('Erro ao remover item')));
/** Limpa o carrinho de um usuário. */
const clearCart = (userId=null) => fetch(API_BASE + '/carrinho?user_id=' + encodeURIComponent(userId || ''), { method: 'DELETE', headers: authHeaders() }).then(r => r.ok ? r.json() : Promise.reject(new Error('Erro ao limpar carrinho')));
/** Cria um novo pedido. */
const createOrder = (payload) => api('pedidos', { method: 'POST', body: JSON.stringify(payload) });

// API helpers (Gerenciamento)
/** Busca a lista de usuários. */
const getUsers = () => api('usuarios');
/** Busca a lista de setores. */
const getSetores = () => api('setores');
/** Busca a lista de falecidos. */
const getFalecidos = () => api('falecidos');
/** Busca a lista de pedidos. */
const getOrders = () => api('pedidos');
/** Busca a lista de registros financeiros. */
const getFinanceiro = () => api('financeiro');

// NOVAS API helpers (CREATE)
/** Cria um novo usuário. */
const createUser = (payload) => api('usuarios', { method: 'POST', body: JSON.stringify(payload) });
/** Cria um novo setor. */
const createSetor = (payload) => api('setores', { method: 'POST', body: JSON.stringify(payload) });
/** Cria um novo registro de falecido. */
const createFalecido = (payload) => api('falecidos', { method: 'POST', body: JSON.stringify(payload) });
/** Cria um novo registro financeiro. */
const createFinanceiro = (payload) => api('financeiro', { method: 'POST', body: JSON.stringify(payload) });
// --- FIM NOVAS API helpers (CREATE) ---

// NOVA API helper
/** Busca a lista de vagas por setor. */
const getSetorVagas = () => api('setores/vagas');

// NOVA API helper
/** Atribui uma vaga a um falecido. */
const assignVaga = (falecidoId, payload) => api(`falecidos/${falecidoId}/atribuir-vaga`, { method: 'PUT', body: JSON.stringify(payload) });

/**
 * Exclui um registro de falecido.
 * @param {number} falecidoId - O ID do falecido a ser excluído.
 */
async function deleteFalecido(falecidoId) {
    return api(`falecidos/${falecidoId}`, { method: 'DELETE' });
}

/**
 * Busca os dados de um único usuário.
 * @param {number} userId - O ID do usuário.
 */
async function getUser(userId) {
    return api(`usuarios/${userId}`);
}

/**
 * Busca os dados de um único setor.
 * @param {number} setorId - O ID do setor.
 */
async function getSetor(setorId) {
    return api(`setores/${setorId}`);
}

/**
 * Atualiza os dados de um usuário.
 * @param {number} userId - O ID do usuário a ser atualizado.
 * @param {object} payload - Os novos dados do usuário.
 */
async function updateUser(userId, payload) {
    return api(`usuarios/${userId}`, { method: 'PUT', body: JSON.stringify(payload) });
}

/**
 * Atualiza os dados de um setor.
 * @param {number} setorId - O ID do setor a ser atualizado.
 * @param {object} payload - Os novos dados do setor.
 */
async function updateSetor(setorId, payload) {
    return api(`setores/${setorId}`, { method: 'PUT', body: JSON.stringify(payload) });
}

/**
 * Exclui um usuário.
 * @param {number} userId - O ID do usuário a ser excluído.
 */
async function deleteUser(userId) {
    return api(`usuarios/${userId}`, { method: 'DELETE' });
}

/**
 * Exclui um setor.
 * @param {number} setorId - O ID do setor a ser excluído.
 */
async function deleteSetor(setorId) {
    return api(`setores/${setorId}`, { method: 'DELETE' });
}

/**
 * Associa um falecido a um usuário.
 * @param {number} falecidoId - O ID do falecido.
 * @param {number} userId - O ID do usuário.
 */
async function associateFalecidoToUser(falecidoId, userId) {
    return api(`falecidos/${falecidoId}/associar`, {
        method: 'POST',
        body: JSON.stringify({ user_id: userId })
    });
}

/**
 * Busca os falecidos associados a um usuário.
 * @param {number} userId - O ID do usuário.
 */
async function getFalecidosByUser(userId) {
    return api(`usuarios/${userId}/falecidos`);
}

/**
 * Busca a lista de pedidos.
 */
async function getPedidos() {
    return api('pedidos');
}

/**
 * Atualiza o status de um pedido (Aprovado/Rejeitado).
 * @param {number} pedidoId - O ID do pedido.
 * @param {string} status - O novo status ('Aprovado' ou 'Rejeitado').
 */
async function updatePedidoStatus(pedidoId, status) {
    return api(`pedidos/${pedidoId}/aprovar`, {
        method: 'PUT',
        body: JSON.stringify({ status }),
        skipEncryption: true // Adicionado para evitar erro de decriptografia
    });
}

// DOM helpers
/** Atalho para document.getElementById. */
const el = id => document.getElementById(id);

// ------------------------------------
// VIEWS (Templates HTML)
// ------------------------------------

// Views (Originals)
/** Renderiza o formulário de login. */
function renderLogin(){
    return `
        <div class="card">
            <h2>Entrar</h2>
            <div class="form-row"><label>Usuário</label><input id="loginUser" class="input"/></div>
            <div class="form-row"><label>Senha</label><input id="loginPass" type="password" class="input"/></div>
            <div class="footer-actions">
                <button id="doLogin" class="btn btn-primary">Entrar</button>
                <button id="goRegister" class="btn btn-ghost">Criar Conta</button>
            </div>
            <div class="extra-actions">
                <a href="#forgot-password" class="link">Esqueceu a senha?</a>
            </div>
        </div>`;
}

/** Renderiza a página do catálogo de produtos. */
function renderCatalog(){
    return `
        <div class="card">
            <h2>Catálogo</h2>
            <div id="catalogGrid" class="grid">Carregando...</div>
            <div class="footer-actions"><button id="goCart" class="btn btn-ghost">Ver carrinho</button></div>
        </div>`;
}

/** Renderiza a página do carrinho de compras. */
function renderCart(){
    return `
        <div class="card">
            <h2>Carrinho</h2>
            <div id="cartBody">Carregando...</div>
            <div class="footer-actions"><button id="goCheckout" class="btn btn-primary">Finalizar Pedido</button> <button id="backCatalog" class="btn btn-ghost">Continuar</button></div>
        </div>`;
}

/** Renderiza o formulário de checkout. */
function renderCheckout(){
    return `
        <div class="card">
            <h2>Checkout</h2>
            <form id="checkoutForm">
                <div class="form-row"><label>Nome</label><input id="ckNome" class="input" required></div>
                <div class="form-row"><label>CPF</label><input id="ckCPF" class="input" required></div>
                <div class="form-row"><label>Email</label><input id="ckEmail" class="input" required></div>
                <div class="form-row"><label>Telefone</label><input id="ckTel" class="input" required></div>
                <div class="form-row"><label>Forma de Pagamento</label>
                    <select id="ckPagto" class="input"><option value="pix">Pix</option><option value="boleto">Boleto</option><option value="cartao">Cartão</option></select>
                </div>
                <div id="checkoutSummary"></div>
                <div class="footer-actions"><button type="submit" class="btn btn-primary">Enviar pedido</button> <button type="button" id="cancelCheckout" class="btn btn-ghost">Cancelar</button></div>
            </form>
        </div>`;
}

/** Renderiza a página de sucesso após a criação de um pedido. */
function renderSuccess(){
    return `
        <div class="card">
            <h2>Pedido realizado</h2>
            <p>Pedido registrado com sucesso.</p>
            <button class="btn btn-primary" id="newCatalog">Novo pedido</button>
        </div>`;
}

/** Renderiza a página de acesso negado. */
function renderAccessDenied(){
     return `
        <div class="card" style="border-left: 5px solid red;">
            <h2>Acesso Negado</h2>
            <p>Você não tem permissão para visualizar esta página.</p>
            <p><a href="#catalog" onclick="render()">Voltar ao Catálogo</a></p>
        </div>`;
}

// Views (Gerenciamento)
/** Renderiza a página de gerenciamento de usuários. */
function renderUsers(){
    return `
        <div class="card">
            <h2>Gerenciar Usuários</h2>
            <div id="usersList">Carregando...</div>
            <div class="footer-actions">
                <button class="btn btn-primary" data-route="new-user">Novo Usuário</button>
            </div>
        </div>`;
}

/** Renderiza a página de gerenciamento de setores. */
function renderSetores(){
    return `
        <div class="card">
            <h2>Gerenciar Setores</h2>
            <div id="setoresList">Carregando...</div>
            <div class="footer-actions">
                <button class="btn btn-primary" data-route="new-setor">Novo Setor</button>
            </div>
        </div>`;
}

/** Renderiza a página de gerenciamento de falecidos. */
function renderFalecidos(){
    return `
        <div class="card">
            <h2>Gerenciar Falecidos</h2>
            <div id="falecidosList">Carregando...</div>
            ${
                currentUser?.role === 'admin'
                    ? `<div class="footer-actions">
                           <button class="btn btn-primary" data-route="new-falecido">Adicionar Falecido</button>
                       </div>`
                    : ''
            }
        </div>`;
}

/** Renderiza a página de visualização de pedidos. */
function renderOrders(){
    return `
        <div class="card">
            <h2>Pedidos Realizados</h2>
            <div id="ordersList">Carregando...</div>
        </div>`;
}

/** Renderiza a página de gerenciamento financeiro. */
function renderFinanceiro() {
    return `
        <div class="card">
            <h2>Gerenciar Financeiro</h2>
            <div id="financeiroList">Carregando...</div>
            <div class="footer-actions">
                <button class="btn btn-primary" data-route="new-financeiro">Novo Registro</button>
            </div>
        </div>`;
}

// NOVAS VIEWS (FORMULÁRIOS DE CRIAÇÃO)
/** Renderiza o formulário de criação de usuário ou registro de conta. */
function renderNewUser(){
    const isAdmin = currentUser && currentUser.role === 'admin';
    return `
        <div class="card">
            <h2>${isAdmin ? 'Novo Usuário' : 'Criar Conta'}</h2>
            <form id="newUserForm">
                <div class="form-row"><label>Nome</label><input id="uName" class="input" required></div>
                <div class="form-row"><label>Usuário (Login)</label><input id="uUser" class="input" required></div>
                <div class="form-row"><label>Email</label><input id="uEmail" type="email" class="input"></div>
                <div class="form-row"><label>Senha</label><input id="uPass" type="password" class="input" required></div>
                ${isAdmin ? `
                <div class="form-row"><label>Nível (Role)</label>
                    <select id="uRole" class="input">
                        <option value="visitante">Visitante</option>
                        <option value="admin">admin</option>
                    </select>
                </div>
                ` : `
                <div class="form-row terms-agreement">
                    <input type="checkbox" id="termsCheckbox">
                    <label for="termsCheckbox">
                        Eu li e aceito os 
                        <a href="/termos-de-uso.html" target="_blank">Termos de Uso</a> e a 
                        <a href="/politica-de-privacidade.html" target="_blank">Política de Privacidade</a>.
                    </label>
                </div>
                `}
                <div class="footer-actions">
                    <button type="submit" id="saveUserBtn" class="btn btn-primary" ${isAdmin ? '' : 'disabled'}>Salvar</button>
                    <button type="button" class="btn btn-ghost" onclick="location.hash='${isAdmin ? '#users' : '#login'}';render()">Cancelar</button>
                </div>
            </form>
        </div>`;
}

/** Renderiza o formulário de criação de setor. */
function renderNewSetor(){
    return `
        <div class="card">
            <h2>Novo Setor</h2>
            <form id="newSetorForm">
                <div class="form-row"><label>Nome do Setor</label><input id="sName" class="input" required></div>
                <div class="form-row"><label>Vagas Disponíveis</label><input id="sVagas" type="number" min="0" max="150" class="input" required></div>
                <div class="footer-actions">
                    <button type="submit" class="btn btn-primary">Salvar</button>
                    <button type="button" class="btn btn-ghost" onclick="location.hash='#setores';render()">Cancelar</button>
                </div>
            </form>
        </div>`;
}

/** Renderiza o formulário de adição de falecido. */
function renderNewFalecido(){
    return `
        <div class="card">
            <h2>Adicionar Falecido</h2>
            <form id="newFalecidoForm">
                <div class="form-row"><label>Nome</label><input id="fName" class="input" required></div>
                <div class="form-row"><label>Ano de Nascimento</label><input id="fNascimento" type="number" min="1000" max="2100" class="input" required></div>
                <div class="form-row"><label>Ano da Morte</label><input id="fMorte" type="number" min="1000" max="2100" class="input" required></div>
                <div class="form-row"><label>Setor</label><input id="fSetor" class="input" placeholder="ID do Setor" required></div>
                <div class="form-row"><label>Vaga</label><input id="fVaga" type="number" min="1" class="input" required></div>
                <div class="footer-actions">
                    <button type="submit" class="btn btn-primary">Salvar</button>
                    <button type="button" class="btn btn-ghost" onclick="location.hash='#falecidos';render()">Cancelar</button>
                </div>
            </form>
        </div>`;
}

/** Renderiza o formulário de criação de registro financeiro. */
function renderNewFinanceiro(){
    return `
        <div class="card">
            <h2>Novo Registro Financeiro</h2>
            <form id="newFinanceiroForm">
                <div class="form-row"><label>Tipo</label>
                    <select id="fnTipo" class="input">
                        <option value="receita">Receita</option>
                        <option value="despesa">Despesa</option>
                    </select>
                </div>
                <div class="form-row"><label>Descrição</label><input id="fnDescricao" class="input" required></div>
                <div class="form-row"><label>Valor</label><input id="fnValor" type="number" step="0.01" class="input" required></div>
                <div class="form-row"><label>Data</label><input id="fnData" type="date" class="input" required></div>
                <div class="footer-actions">
                    <button type="submit" class="btn btn-primary">Salvar</button>
                    <button type="button" class="btn btn-ghost" onclick="location.hash='#financeiro';render()">Cancelar</button>
                </div>
            </form>
        </div>`;
}

// NOVA VIEW
/** Renderiza a página de visualização de vagas por setor. */
function renderSetorVagas() {
    return `
        <div class="card">
            <h2>Vagas por Setor</h2>
            <div id="setoresButtons">Carregando setores...</div>
            <div id="setorVagasList"></div>
        </div>`;
}

// NOVA VIEW
/**
 * Renderiza o formulário para atribuir uma vaga a um falecido.
 * @param {number} falecidoId - O ID do falecido.
 */
function renderAssignVaga(falecidoId) {
    return `
        <div class="card">
            <h2>Atribuir Vaga</h2>
            <form id="assignVagaForm">
                <div class="form-row"><label>Setor</label><input id="setorId" class="input" required></div>
                <div class="form-row"><label>Vaga</label><input id="vagaNumero" type="number" class="input" required></div>
                <div class="footer-actions">
                    <button type="submit" class="btn btn-primary">Atribuir</button>
                    <button type="button" class="btn btn-ghost" onclick="location.hash='#falecidos';render()">Cancelar</button>
                </div>
            </form>
        </div>`;
}

/** Renderiza a página inicial (home). */
function renderHome() {
    return `
        <div class="card home-card">
            <h2>Bem-vindo ao Cemitério Online</h2>
            <p>Nosso objetivo é oferecer um sistema moderno e eficiente para a gestão de cemitérios, proporcionando organização e praticidade para administradores e visitantes.</p>
            <p>Com nossa plataforma, você pode:</p>
            <ul>
                <li>Gerenciar setores e vagas disponíveis.</li>
                <li>Registrar informações de falecidos de forma segura.</li>
                <li>Controlar o financeiro e gerar relatórios.</li>
                <li>Explorar serviços e produtos oferecidos.</li>
            </ul>
            <p>Estamos comprometidos em oferecer uma experiência simples e intuitiva, garantindo que todas as informações sejam acessíveis e bem organizadas.</p>
            <p><strong>Entre e descubra como podemos ajudar!</strong></p>
        </div>
    `;
}

/** Renderiza a página de listagem de pedidos. */
function renderPedidos() {
    return `
        <div class="card">
            <h2>Pedidos Realizados</h2>
            <div id="pedidosList">Carregando...</div>
        </div>`;
}

// --- NOVAS VIEWS PARA PERFIL DE USUÁRIO ---
/** Renderiza a página de perfil do usuário logado. */
function renderProfile() {
    if (!currentUser) return renderAccessDenied();
    return `
        <div class="card">
            <h2>Meu Perfil</h2>
            <div class="profile-info">
                <p><strong>Nome:</strong> ${currentUser.name}</p>
                <p><strong>Usuário:</strong> ${currentUser.username}</p>
                <p><strong>Email:</strong> ${currentUser.email}</p>
                <p><strong>Nível:</strong> ${currentUser.role}</p>
            </div>
            <div class="footer-actions">
                <button id="editProfileBtn" class="btn btn-primary">Editar Perfil</button>
                <button id="deleteProfileBtn" class="btn btn-danger">Excluir Conta</button>
            </div>
        </div>
    `;
}

/** Renderiza o formulário de edição de perfil do usuário. */
function renderEditProfile() {
    if (!currentUser) return renderAccessDenied();
    return `
        <div class="card">
            <h2>Editar Perfil</h2>
            <form id="editProfileForm">
                <div class="form-row"><label>Nome</label><input id="uName" class="input" value="${currentUser.name}" required></div>
                <div class="form-row"><label>Usuário (Login)</label><input id="uUser" class="input" value="${currentUser.username}" required></div>
                <div class="form-row"><label>Email</label><input id="uEmail" type="email" class="input" value="${currentUser.email || ''}"></div>
                <div class="form-row"><label>Nova Senha (deixe em branco para não alterar)</label><input id="uPass" type="password" class="input"></div>
                <div class="footer-actions">
                    <button type="submit" class="btn btn-primary">Salvar Alterações</button>
                    <button type="button" class="btn btn-ghost" onclick="location.hash='#profile';render()">Cancelar</button>
                </div>
            </form>
        </div>
    `;
}

// --- NOVAS VIEWS PARA RECUPERAÇÃO DE SENHA ---
/** Renderiza o formulário para solicitar a recuperação de senha. */
function renderForgotPassword() {
    return `
        <div class="card">
            <h2>Recuperar Senha</h2>
            <p>Informe seu e-mail e nome de usuário para continuar.</p>
            <form id="forgotPasswordForm">
                <div class="form-row">
                    <label>Email</label>
                    <input id="fpEmail" type="email" class="input" required/>
                </div>
                <div class="form-row">
                    <label>Nome de Usuário</label>
                    <input id="fpUsername" type="text" class="input" required/>
                </div>
                <div class="footer-actions">
                    <button type="submit" class="btn btn-primary">Continuar</button>
                    <button type="button" class="btn btn-ghost" onclick="location.hash='#login';render()">Cancelar</button>
                </div>
            </form>
        </div>`;
}

/**
 * Renderiza o formulário para redefinir a senha.
 * @param {string} token - O token de recuperação.
 */
function renderResetPassword(token) {
    return `
        <div class="card">
            <h2>Redefinir Senha</h2>
            <form id="resetPasswordForm">
                <div class="form-row">
                    <label>Nova Senha</label>
                    <input id="rpPassword" type="password" class="input" required/>
                </div>
                <div class="form-row">
                    <label>Confirmar Nova Senha</label>
                    <input id="rpConfirmPassword" type="password" class="input" required/>
                </div>
                <div class="footer-actions">
                    <button type="submit" class="btn btn-primary">Redefinir Senha</button>
                </div>
            </form>
        </div>`;
}

// ------------------------------------
// BINDS (Lógica e API Calls)
// ------------------------------------

// Binds (Originais)
/**
 * Associa a lógica ao formulário de login.
 * @param {HTMLElement} container - O elemento que contém a view.
 */
async function bindLogin(container){
    const btn = el('doLogin');
    if(!btn) return;
    btn.onclick = async () => {
        const u = el('loginUser').value.trim();
        const p = el('loginPass').value;
        if(!u || !p){ alert('Informe usuário e senha'); return; }
        try{
            const res = await login(u,p);
            token = res.access_token;
            currentUser = res.user; // res.user agora contém todos os dados
            localStorage.setItem('cem_access_token', res.access_token);
            localStorage.setItem('cem_refresh_token', res.refresh_token);
            
            // --- REGISTRA A CHAVE PÚBLICA NO SERVIDOR APÓS O LOGIN ---
            await cryptoModule.registerKeyWithServer();

            location.hash = '#catalog';
            render();
        }catch(e){ alert('Erro: ' + e.message); }
    };

    const registerBtn = el('goRegister');
    if (registerBtn) {
        registerBtn.onclick = () => {
            location.hash = '#new-user';
            render();
        };
    }
}

// --- NOVOS BINDS PARA RECUPERAÇÃO DE SENHA ---
/**
 * Associa a lógica ao formulário de "esqueci minha senha".
 * @param {HTMLElement} container - O elemento que contém a view.
 */
async function bindForgotPassword(container) {
    const form = el('forgotPasswordForm');
    if (!form) return;
    form.onsubmit = async (e) => {
        e.preventDefault();
        const email = el('fpEmail').value;
        const username = el('fpUsername').value;
        try {
            const res = await forgotPassword(email, username);
            // Redireciona para a tela de reset com o token recebido
            location.hash = `#reset-password/${res.token}`;
            render();
        } catch (e) {
            alert('Erro: ' + e.message);
        }
    };
}

/**
 * Associa a lógica ao formulário de redefinição de senha.
 * @param {HTMLElement} container - O elemento que contém a view.
 * @param {string} token - O token de recuperação.
 */
async function bindResetPassword(container, token) {
    const form = el('resetPasswordForm');
    if (!form) return;
    form.onsubmit = async (e) => {
        e.preventDefault();
        const password = el('rpPassword').value;
        const confirmPassword = el('rpConfirmPassword').value;

        if (password !== confirmPassword) {
            alert('As senhas não coincidem.');
            return;
        }

        try {
            const res = await resetPassword(token, password);
            alert(res.message);
            location.hash = '#login';
            render();
        } catch (e) {
            alert('Erro: ' + e.message);
        }
    };
}

/**
 * Carrega e exibe os produtos do catálogo.
 * @param {HTMLElement} container - O elemento que contém a view.
 */
async function bindCatalog(container){
    const grid = container.querySelector('#catalogGrid');
    if(!grid) return;
    try{
        const produtos = await getCatalog();
        grid.innerHTML = '';
        produtos.forEach(p => {
            const card = document.createElement('div');
            card.className = 'card';
            card.style.minWidth = '220px';
            card.innerHTML = `<h3>${p.nome}</h3><p class="meta">${p.descricao||''}</p><div><b>R$ ${Number(p.preco).toFixed(2)}</b></div><button class="btn btn-primary" data-add="${p.id}">Adicionar</button>`;
            grid.appendChild(card);
        });
        grid.querySelectorAll('[data-add]').forEach(btn => btn.onclick = async ()=>{
            try{
                const id = Number(btn.dataset.add);
                await addCartItem(id,1,currentUser?.id||null);
                alert('Adicionado ao carrinho');
            }catch(e){ alert('Erro: '+e.message); }
        });
    }catch(e){ grid.innerHTML = '<p style="color:red">Erro ao carregar catálogo</p>'; }

    const goCart = container.querySelector('#goCart'); if(goCart) goCart.onclick = ()=>{ location.hash = '#cart'; render(); };
}

/**
 * Carrega e exibe os itens do carrinho de compras.
 * @param {HTMLElement} container - O elemento que contém a view.
 */
async function bindCart(container){
    const body = container.querySelector('#cartBody');
    try{
        const cart = await getCart(currentUser?.id||null);
        if(!cart || !cart.length){ body.innerHTML = '<p>Carrinho vazio</p>'; return; }
        const catalog = await getCatalog();
        let total = 0;
        const rows = cart.map(item => {
            const prod = catalog.find(p=>p.id == item.produto_id) || { nome: 'Produto', preco: 0 };
            const subtotal = Number(prod.preco||0) * item.quantidade;
            total += subtotal;
            return `<div class="cart-row" data-id="${item.id}"><div>${prod.nome} — R$ ${Number(prod.preco||0).toFixed(2)} x ${item.quantidade}</div><div><button data-rm="${item.id}" class="btn btn-danger">Remover</button></div></div>`;
        }).join('');
        body.innerHTML = rows + `<h3>Total: R$ ${total.toFixed(2)}</h3>`;
        body.querySelectorAll('[data-rm]').forEach(btn => btn.onclick = async ()=>{
            try{ await removeCartItem(btn.dataset.rm); render(); }catch(e){ alert('Erro: '+e.message); }
        });
    }catch(e){ body.innerHTML = '<p style="color:red">Erro ao carregar carrinho</p>'; }

    const goCheckout = container.querySelector('#goCheckout'); if(goCheckout) goCheckout.onclick = ()=>{ location.hash = '#checkout'; render(); };
    const back = container.querySelector('#backCatalog'); if(back) back.onclick = ()=>{ location.hash = '#catalog'; render(); };
}

// --- NOVOS BINDS PARA PERFIL ---
/**
 * Associa a lógica aos botões da página de perfil (editar, excluir).
 * @param {HTMLElement} container - O elemento que contém a view.
 */
async function bindProfile(container) {
    if (!currentUser) return;

    const editBtn = el('editProfileBtn');
    if (editBtn) {
        editBtn.onclick = () => {
            location.hash = '#edit-profile';
            render();
        };
    }

    const deleteBtn = el('deleteProfileBtn');
    if (deleteBtn) {
        deleteBtn.onclick = async () => {
            const confirmation = confirm('Tem certeza que deseja excluir sua conta? Esta ação é irreversível.');
            if (confirmation) {
                try {
                    await deleteUser(currentUser.id);
                    alert('Sua conta foi excluída com sucesso.');
                    logoutUser(); // Usa a nova função de logout
                } catch (e) {
                    alert('Erro ao excluir sua conta: ' + e.message);
                }
            }
        };
    }
}

/**
 * Associa a lógica ao formulário de edição de perfil.
 * @param {HTMLElement} container - O elemento que contém a view.
 */
async function bindEditProfile(container) {
    const form = container.querySelector('#editProfileForm');
    if (!form) return;

    form.onsubmit = async (e) => {
        e.preventDefault();
        const password = el('uPass').value;
        const payload = {
            name: el('uName').value,
            username: el('uUser').value,
            email: el('uEmail').value,
        };
        // Só envia a senha se ela for alterada
        if (password) {
            payload.password = password;
        }

        try {
            await updateUser(currentUser.id, payload);
            alert('Perfil atualizado com sucesso! Por favor, faça login novamente.');
            logoutUser(); // Usa a nova função de logout
        } catch (e) {
            alert('Erro ao atualizar o perfil: ' + e.message);
        }
    };
}

// Binds (Gerenciamento)
/**
 * Carrega e exibe a lista de usuários, associando eventos aos botões.
 * @param {HTMLElement} container - O elemento que contém a view.
 */
async function bindUsers(container){
    const list = container.querySelector('#usersList');
    if(!list) return;

    // Adicionar binding para o botão 'Novo Usuário'
    const newUserBtn = container.querySelector('button[data-route="new-user"]');
    if (newUserBtn) {
        newUserBtn.onclick = () => { location.hash = '#new-user'; render(); };
    }

    try{
        const users = await getUsers();
        let html = users.map(u => `
            <div class="list-item user-item">
                <div>
                    <strong>${u.name}</strong> (${u.username})<br>
                    <small>Email: ${u.email} | Nível: ${u.role}</small>
                </div>
                <div>
                    <button class="btn btn-ghost" data-edit="${u.id}">Editar</button>
                    <button class="btn btn-danger" data-delete="${u.id}">Excluir</button>
                </div>
            </div>
        `).join('');
        list.innerHTML = html;
        // Adicionar binding para o botão 'Novo Usuário'
        container.querySelector('button[data-route="new-user"]').onclick = () => { location.hash = '#new-user'; render(); };
        // Bindings para botões de ação (Editar/Deletar) iriam aqui.
        list.querySelectorAll('[data-edit]').forEach(btn => {
            btn.onclick = async () => {
                const userId = btn.dataset.edit;
                const user = await getUser(userId);
                renderEditUser(user);
            };
        });

        list.querySelectorAll('[data-delete]').forEach(btn => {
            btn.onclick = async () => {
                const userId = btn.dataset.delete;
                const confirmDelete = confirm('Tem certeza de que deseja excluir este usuário? Esta ação não pode ser desfeita.');
                if (confirmDelete) {
                    try {
                        await deleteUser(userId);
                        alert('Usuário excluído com sucesso!');
                        render();
                    } catch (e) {
                        alert('Erro ao excluir usuário: ' + e.message);
                    }
                }
            };
        });
    }catch(e){
        list.innerHTML = '<p style="color:red">Erro ao carregar usuários</p>';
    }
}

/**
 * Carrega e exibe a lista de setores, associando eventos aos botões.
 * @param {HTMLElement} container - O elemento que contém a view.
 */
async function bindSetores(container){
    const list = container.querySelector('#setoresList');
    if(!list) return;
    try{
        const setores = await getSetores();
        let html = setores.map(s => `
            <div class="list-item setor-item">
                <div>
                    <strong>${s.name}</strong><br>
                    <small>Vagas: ${s.vagas}</small>
                </div>
                <div>
                    <button class="btn btn-ghost" data-edit="${s.id}">Editar</button>
                    <button class="btn btn-danger" data-delete="${s.id}">Excluir</button>
                </div>
            </div>
        `).join('');
        list.innerHTML = html;
        // Adicionar binding para o botão 'Novo Setor'
        container.querySelector('button[data-route="new-setor"]').onclick = () => { location.hash = '#new-setor'; render(); };
        list.querySelectorAll('[data-edit]').forEach(btn => {
            btn.onclick = async () => {
                const setorId = btn.dataset.edit;
                const setor = await getSetor(setorId);
                renderEditSetor(setor);
            };
        });

        list.querySelectorAll('[data-delete]').forEach(btn => {
            btn.onclick = async () => {
                const setorId = btn.dataset.delete;
                const confirmDelete = confirm('Tem certeza de que deseja excluir este setor? Esta ação não pode ser desfeita.');
                if (confirmDelete) {
                    try {
                        await deleteSetor(setorId);
                        alert('Setor excluído com sucesso!');
                        render();
                    } catch (e) {
                        alert('Erro ao excluir setor: ' + e.message);
                    }
                }
            };
        });
    }catch(e){
        list.innerHTML = '<p style="color:red">Erro ao carregar setores</p>';
    }
}

/**
 * Carrega e exibe a lista de falecidos, associando eventos aos botões.
 * @param {HTMLElement} container - O elemento que contém a view.
 */
async function bindFalecidos(container) {
    const list = container.querySelector('#falecidosList');
    if (!list) return;

    // Adicionar binding para o botão 'Adicionar Falecido'
    const newFalecidoBtn = container.querySelector('button[data-route="new-falecido"]');
    if (newFalecidoBtn) {
        newFalecidoBtn.onclick = () => { location.hash = '#new-falecido'; render(); };
    }

    // Verifique se o usuário está logado
    if (!currentUser) {
        list.innerHTML = '<p style="color:red">Você precisa estar logado para visualizar os falecidos.</p>';
        return;
    }

    try {
        const falecidos = await getFalecidos();
        let html = falecidos.map(f => `
            <div class="list-item falecido-item">
                <div>
                    <strong>${f.name}</strong> (Nasc: ${f.anonascimento} - Morte: ${f.anomorte})<br>
                    <small>Setor: ${f.setor_nome || 'Não atribuído'}, Vaga: ${f.vaga || 'N/A'}</small><br>
                    <small>Planos: ${f.planos || 'Nenhum'}</small><br>
                    <small>Usuários Associados: ${f.usuarios_associados || 'Nenhum'}</small>
                </div>
                <div class="actions">
                    ${currentUser?.role === 'admin' ? `
                        <button class="btn btn-ghost" data-edit="${f.id}">Editar</button>
                        <button class="btn btn-danger" data-delete="${f.id}">Excluir</button>
                        <button class="btn btn-primary" data-associate="${f.id}">Associar</button>
                    ` : ''}
                </div>
            </div>
        `).join('');
        list.innerHTML = html;

        // Bind para ações de administrador
        if (currentUser?.role === 'admin') {
            list.querySelectorAll('[data-edit]').forEach(btn => {
                btn.onclick = () => {
                    const falecidoId = btn.dataset.edit;
                    renderEditFalecido(falecidoId);
                };
            });

            list.querySelectorAll('[data-delete]').forEach(btn => {
                btn.onclick = async () => {
                    const falecidoId = btn.dataset.delete;
                    const confirmDelete = confirm('Tem certeza de que deseja excluir este registro?');
                    if (confirmDelete) {
                        try {
                            await deleteFalecido(falecidoId);
                            alert('Registro excluído com sucesso!');
                            render();
                        } catch (e) {
                            alert('Erro ao excluir registro: ' + e.message);
                        }
                    }
                };
            });

            list.querySelectorAll('[data-associate]').forEach(btn => {
                btn.onclick = async () => {
                    const falecidoId = btn.dataset.associate;
                    const userId = prompt('Informe o ID do usuário para associar:');
                    if (userId) {
                        try {
                            await associateFalecidoToUser(falecidoId, userId);
                            alert('Falecido associado ao usuário com sucesso!');
                            render();
                        } catch (e) {
                            alert('Erro ao associar falecido: ' + e.message);
                        }
                    }
                };
            });
        }
    } catch (e) {
        list.innerHTML = '<p style="color:red">Erro ao carregar falecidos: ' + e.message + '</p>';
    }
}

/**
 * Carrega e exibe a lista de pedidos, associando eventos aos botões de admin.
 * @param {HTMLElement} container - O elemento que contém a view.
 */
async function bindPedidos(container) {
    const list = container.querySelector('#pedidosList');
    if (!list) return;

    try {
        const pedidos = await getPedidos();
        // Ordena os pedidos do mais recente para o mais antigo
        pedidos.sort((a, b) => b.id - a.id);
        
        let html = pedidos.map(p => `
            <div class="list-item pedido-item">
                <div>
                    <strong>Pedido #${p.id}</strong> (Total: R$ ${Number(p.total).toFixed(2)})<br>
                    <small>Status: ${p.status} | Cliente: ${p.nome} | Data: ${new Date(p.created_at).toLocaleDateString()}</small>
                </div>
                <div class="actions">
                    ${currentUser?.role === 'admin' ? `
                        <button class="btn btn-ghost" data-edit="${p.id}">Editar</button>
                        <button class="btn btn-primary" data-aprovar="${p.id}">Aprovar</button>
                        <button class="btn btn-danger" data-rejeitar="${p.id}">Rejeitar</button>
                    ` : ''}
                </div>
            </div>
        `).join('');
        list.innerHTML = html;

        if (currentUser?.role === 'admin') {
            // Bind para o botão Editar (atualmente, permite mudar o status)
            list.querySelectorAll('[data-edit]').forEach(btn => {
                btn.onclick = async () => {
                    const pedidoId = btn.dataset.edit;
                    const novoStatus = prompt('Informe o novo status do pedido (ex: Aprovado, Pendente, Rejeitado):', 'Aprovado');
                    if (novoStatus) {
                        try {
                            await updatePedidoStatus(pedidoId, novoStatus);
                            alert('Status do pedido atualizado com sucesso!');
                            render();
                        } catch (e) {
                            alert('Erro ao atualizar status: ' + e.message);
                        }
                    }
                };
            });

            list.querySelectorAll('[data-aprovar]').forEach(btn => {
                btn.onclick = async () => {
                    const pedidoId = btn.dataset.aprovar;
                    try {
                        await updatePedidoStatus(pedidoId, 'Aprovado');
                        alert('Pedido aprovado com sucesso!');
                        render();
                    } catch (e) {
                        alert('Erro ao aprovar pedido: ' + e.message);
                    }
                };
            });

            list.querySelectorAll('[data-rejeitar]').forEach(btn => {
                btn.onclick = async () => {
                    const pedidoId = btn.dataset.rejeitar;
                    try {
                        await updatePedidoStatus(pedidoId, 'Rejeitado');
                        alert('Pedido rejeitado com sucesso!');
                        render();
                    } catch (e) {
                        alert('Erro ao rejeitar pedido: ' + e.message);
                    }
                };
            });
        }
    } catch (e) {
        list.innerHTML = '<p style="color:red">Erro ao carregar pedidos: ' + e.message + '</p>';
    }
}

/**
 * Renderiza e associa a lógica ao formulário de edição de um falecido (atribuir vaga).
 * @param {number} falecidoId - O ID do falecido a ser editado.
 */
function renderEditFalecido(falecidoId) {
    const app = document.getElementById('app');
    app.innerHTML = `
        <div class="card">
            <h2>Editar Falecido</h2>
            <form id="editFalecidoForm">
                <div class="form-row"><label>Setor</label><input id="setorId" class="input" required></div>
                <div class="form-row"><label>Vaga</label><input id="vagaNumero" type="number" class="input" required></div>
                <div class="footer-actions">
                    <button type="submit" class="btn btn-primary">Salvar</button>
                    <button type="button" class="btn btn-ghost" onclick="location.hash='#falecidos';render()">Cancelar</button>
                </div>
            </form>
        </div>
    `;

    // Bind para o formulário de edição
    const form = document.getElementById('editFalecidoForm');
    form.onsubmit = async (e) => {
        e.preventDefault();
        const payload = {
            setor: document.getElementById('setorId').value,
            vaga: Number(document.getElementById('vagaNumero').value)
        };
        try {
            await assignVaga(falecidoId, payload);
            alert('Vaga atualizada com sucesso!');
            location.hash = '#falecidos';
            render();
        } catch (e) {
            alert('Erro ao atualizar vaga: ' + e.message);
        }
    };
}

/**
 * Carrega e exibe a lista de registros financeiros, associando eventos aos botões.
 * @param {HTMLElement} container - O elemento que contém a view.
 */
async function bindFinanceiro(container) {
    const list = container.querySelector('#financeiroList');
    if (!list) return;

    // Adicionar binding para o botão 'Novo Registro'
    const newRegistroBtn = container.querySelector('button[data-route="new-financeiro"]');
    if (newRegistroBtn) {
        newRegistroBtn.onclick = () => { location.hash = '#new-financeiro'; render(); };
    }

    try {
        const items = await getFinanceiro();
        let html = items.map(i => `
            <div class="list-item financeiro-item">
                <div>
                    <strong>${i.descricao}</strong> (${i.tipo})<br>
                    <small>Valor: R$ ${Number(i.valor).toFixed(2)} | Data: ${i.data} | Status: ${i.status || 'Pendente'}</small>
                </div>
                <div class="actions">
                    <button class="btn btn-ghost" data-edit="${i.id}">Editar</button>
                    <button class="btn btn-danger" data-delete="${i.id}">Excluir</button>
                </div>
            </div>
        `).join('');
        list.innerHTML = html;

        // Bind para editar
        list.querySelectorAll('[data-edit]').forEach(btn => {
            btn.onclick = async () => {
                const financeiroId = btn.dataset.edit;
                const financeiro = await getFinanceiroById(financeiroId);
                renderEditFinanceiro(financeiro);
            };
        });

        // Bind para excluir
        list.querySelectorAll('[data-delete]').forEach(btn => {
            btn.onclick = async () => {
                const financeiroId = btn.dataset.delete;
                const confirmDelete = confirm('Tem certeza de que deseja excluir este registro? Esta ação não pode ser desfeita.');
                if (confirmDelete) {
                    try {
                        await deleteFinanceiro(financeiroId);
                        alert('Registro excluído com sucesso!');
                        render();
                    } catch (e) {
                        alert('Erro ao excluir registro: ' + e.message);
                    }
                }
            };
        });
    } catch (e) {
        list.innerHTML = '<p style="color:red">Erro ao carregar financeiro</p>';
    }
}

/**
 * Renderiza e associa a lógica ao formulário de edição de um registro financeiro.
 * @param {object} financeiro - O objeto do registro financeiro a ser editado.
 */
function renderEditFinanceiro(financeiro) {
    const app = document.getElementById('app');
    app.innerHTML = `
        <div class="card">
            <h2>Editar Registro Financeiro</h2>
            <form id="editFinanceiroForm">
                <div class="form-row"><label>Tipo</label>
                    <select id="fnTipo" class="input">
                        <option value="receita" ${financeiro.tipo === 'receita' ? 'selected' : ''}>Receita</option>
                        <option value="despesa" ${financeiro.tipo === 'despesa' ? 'selected' : ''}>Despesa</option>
                    </select>
                </div>
                <div class="form-row"><label>Descrição</label><input id="fnDescricao" class="input" value="${financeiro.descricao}" required></div>
                <div class="form-row"><label>Valor</label><input id="fnValor" type="number" step="0.01" class="input" value="${financeiro.valor}" required></div>
                <div class="form-row"><label>Data</label><input id="fnData" type="date" class="input" value="${financeiro.data}" required></div>
                <div class="form-row"><label>Status</label>
                    <select id="fnStatus" class="input">
                        <option value="pendente" ${financeiro.status.toLowerCase() === 'pendente' ? 'selected' : ''}>Pendente</option>
                        <option value="pago" ${financeiro.status.toLowerCase() === 'pago' ? 'selected' : ''}>Pago</option>
                    </select>
                </div>
                <div class="footer-actions">
                    <button type="submit" class="btn btn-primary">Salvar</button>
                    <button type="button" class="btn btn-ghost" onclick="location.hash='#financeiro';render()">Cancelar</button>
                </div>
            </form>
        </div>
    `;

    const form = document.getElementById('editFinanceiroForm');
    form.onsubmit = async (e) => {
        e.preventDefault();
        const payload = {
            tipo: document.getElementById('fnTipo').value,
            descricao: document.getElementById('fnDescricao').value,
            valor: Number(document.getElementById('fnValor').value),
            data: document.getElementById('fnData').value,
            status: document.getElementById('fnStatus').value
        };
        try {
            await updateFinanceiro(financeiro.id, payload);
            alert('Registro atualizado com sucesso!');
            location.hash = '#financeiro';
            render();
        } catch (e) {
            alert('Erro ao atualizar registro: ' + e.message);
        }
    };
}

/**
 * Busca um registro financeiro pelo ID.
 * @param {number} id - O ID do registro.
 */
async function getFinanceiroById(id) {
    return api(`financeiro/${id}`);
}

/**
 * Atualiza um registro financeiro.
 * @param {number} id - O ID do registro.
 * @param {object} payload - Os novos dados do registro.
 */
async function updateFinanceiro(id, payload) {
    return api(`financeiro/${id}`, { 
        method: 'PUT', 
        body: JSON.stringify(payload),
        skipEncryption: true // Adicionado para evitar erro de decriptografia
    });
}

/**
 * Exclui um registro financeiro.
 * @param {number} id - O ID do registro.
 */
async function deleteFinanceiro(id) {
    return api(`financeiro/${id}`, { method: 'DELETE' });
}

// NOVOS BINDS (Lógica de Submissão de Formulário)
/**
 * Associa a lógica ao formulário de criação de novo usuário.
 * @param {HTMLElement} container - O elemento que contém a view.
 */
async function bindNewUser(container){
    const form = container.querySelector('#newUserForm');
    if(!form) return;

    const isAdmin = currentUser && currentUser.role === 'admin';
    const termsCheckbox = el('termsCheckbox');
    const saveBtn = el('saveUserBtn');

    // Habilita/desabilita o botão de salvar para não-admins
    if (!isAdmin && termsCheckbox && saveBtn) {
        termsCheckbox.onchange = () => {
            saveBtn.disabled = !termsCheckbox.checked;
        };
    }

    form.onsubmit = async (e) => {
        e.preventDefault();

        const username = el('uUser').value;
        const password = el('uPass').value;
        const email = el('uEmail').value;

        // --- VALIDAÇÕES ADICIONAIS ---
        if (username.includes(' ')) {
            alert('O nome de usuário não pode conter espaços.');
            return;
        }
        if (password.length < 6) {
            alert('A senha deve ter no mínimo 6 caracteres.');
            return;
        }
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (email && !emailRegex.test(email)) {
            alert('Por favor, insira um endereço de e-mail válido.');
            return;
        }
        // --- FIM DAS VALIDAÇÕES ---

        const roleSelect = el('uRole');
        const payload = {
            name: el('uName').value,
            username: username,
            email: email,
            password: password,
            role: roleSelect ? roleSelect.value : 'visitante' // Default to 'visitante' if selector is not present
        };
        try{
            await createUser(payload);
            alert('Usuário criado com sucesso!');
            // Se não for admin, redireciona para o login após criar a conta
            location.hash = (currentUser && currentUser.role === 'admin') ? '#users' : '#login'; 
            render();
        }catch(e){
            alert('Erro ao criar usuário: ' + e.message);
        }
    };
}

/**
 * Associa a lógica ao formulário de criação de novo setor.
 * @param {HTMLElement} container - O elemento que contém a view.
 */
async function bindNewSetor(container){
    const form = container.querySelector('#newSetorForm');
    if(!form) return;
    form.onsubmit = async (e) => {
        e.preventDefault();
        const payload = {
            name: el('sName').value,
            vagas: Number(el('sVagas').value)
        };
        try{
            await createSetor(payload);
            alert('Setor criado com sucesso!');
            location.hash = '#setores'; 
            render();
        }catch(e){
            alert('Erro ao criar setor: ' + e.message);
        }
    };
}

/**
 * Associa a lógica ao formulário de criação de novo falecido.
 * @param {HTMLElement} container - O elemento que contém a view.
 */
async function bindNewFalecido(container) {
    const form = container.querySelector('#newFalecidoForm');
    if (!form) return;

    form.onsubmit = async (e) => {
        e.preventDefault();
        const payload = {
            name: el('fName').value,
            anoNascimento: Number(el('fNascimento').value),
            anoMorte: Number(el('fMorte').value),
            setor: Number(el('fSetor').value),
            vaga: Number(el('fVaga').value)
        };

        try {
            // Verifique se a vaga está disponível no setor
            const setores = await getSetorVagas();
            const setor = setores.find(s => s.setor_id === payload.setor);

            if (!setor) {
                alert('Setor não encontrado.');
                return;
            }

            const vagaOcupada = setor.vagas.find(v => v.numero === payload.vaga && v.ocupada);
            if (vagaOcupada) {
                alert('A vaga selecionada já está ocupada.');
                return;
            }

            // Crie o falecido e ocupe a vaga
            await createFalecido(payload);
            alert('Falecido registrado com sucesso!');
            location.hash = '#falecidos';
            render();
        } catch (e) {
            alert('Erro ao registrar falecido: ' + e.message);
        }
    };
}

/**
 * Associa a lógica ao formulário de criação de novo registro financeiro.
 * @param {HTMLElement} container - O elemento que contém a view.
 */
async function bindNewFinanceiro(container){
    const form = container.querySelector('#newFinanceiroForm');
    if(!form) return;
    form.onsubmit = async (e) => {
        e.preventDefault();
        const payload = {
            tipo: el('fnTipo').value,
            descricao: el('fnDescricao').value,
            valor: Number(el('fnValor').value),
            data: el('fnData').value
        };
        try{
            await createFinanceiro(payload);
            alert('Registro financeiro criado com sucesso!');
            location.hash = '#financeiro'; 
            render();
        }catch(e){
            alert('Erro ao criar registro financeiro: ' + e.message);
        }
    };
}

// NOVO BIND
/**
 * Carrega os botões de setores e associa eventos para mostrar as vagas.
 * @param {HTMLElement} container - O elemento que contém a view.
 */
async function bindSetorVagas(container) {
    const setoresButtons = container.querySelector('#setoresButtons');
    const vagasList = container.querySelector('#setorVagasList');
    if (!setoresButtons || !vagasList) return;

    try {
        const setores = await getSetores(); // Obtenha a lista de setores
        setoresButtons.innerHTML = setores.map(setor => `
            <button class="btn btn-primary" data-setor-id="${setor.id}">
                ${setor.name}
            </button>
        `).join('');

        // Adicione eventos de clique para os botões
        setoresButtons.querySelectorAll('[data-setor-id]').forEach(button => {
            button.onclick = async () => {
                const setorId = button.dataset.setorId;
                await loadVagasForSetor(setorId, vagasList);
            };
        });
    } catch (e) {
        setoresButtons.innerHTML = '<p style="color:red">Erro ao carregar setores</p>';
    }
}

/**
 * Carrega e exibe as vagas para um setor específico.
 * @param {number} setorId - O ID do setor.
 * @param {HTMLElement} vagasList - O elemento onde a lista de vagas será renderizada.
 */
async function loadVagasForSetor(setorId, vagasList) {
    try {
        const setores = await getSetorVagas(); // Obtenha as vagas de todos os setores
        const setor = setores.find(s => s.setor_id == setorId); // Filtre pelo setor selecionado

        if (!setor) {
            vagasList.innerHTML = '<p style="color:red">Setor não encontrado</p>';
            return;
        }

        vagasList.innerHTML = `
            <h3>Vagas do Setor: ${setor.setor}</h3>
            <ul>
                ${setor.vagas.map(vaga => `
                    <li>Vaga ${vaga.numero}: ${vaga.ocupada ? 'Ocupada' : 'Disponível'}</li>
                `).join('')}
            </ul>
            <button class="btn btn-ghost" id="hideVagas">Ocultar</button>
        `;

        // Adicione o evento para o botão "Ocultar"
        const hideButton = vagasList.querySelector('#hideVagas');
        if (hideButton) {
            hideButton.onclick = () => {
                vagasList.innerHTML = ''; // Limpa a exibição das vagas
            };
        }
    } catch (e) {
        vagasList.innerHTML = '<p style="color:red">Erro ao carregar vagas do setor</p>';
    }
}

// NOVO BIND
/**
 * Associa a lógica ao formulário de atribuição de vaga.
 * @param {HTMLElement} container - O elemento que contém a view.
 * @param {number} falecidoId - O ID do falecido.
 */
async function bindAssignVaga(container, falecidoId) {
    const form = container.querySelector('#assignVagaForm');
    if (!form) return;
    form.onsubmit = async (e) => {
        e.preventDefault();
        const payload = {
            setor: el('setorId').value,
            vaga: Number(el('vagaNumero').value)
        };
        try {
            await assignVaga(falecidoId, payload);
            alert('Vaga atribuída com sucesso!');
            location.hash = '#falecidos';
            render();
        } catch (e) {
            alert('Erro ao atribuir vaga: ' + e.message);
        }
    };
}

/**
 * Renderiza e associa a lógica ao formulário de edição de um usuário.
 * @param {object} user - O objeto do usuário a ser editado.
 */
function renderEditUser(user) {
    const app = document.getElementById('app');
    app.innerHTML = `
        <div class="card">
            <h2>Editar Usuário</h2>
            <form id="editUserForm">
                <div class="form-row"><label>Nome</label><input id="uName" class="input" value="${user.name}" required></div>
                <div class="form-row"><label>Usuário (Login)</label><input id="uUser" class="input" value="${user.username}" required></div>
                <div class="form-row"><label>Email</label><input id="uEmail" type="email" class="input" value="${user.email}"></div>
                <div class="form-row"><label>Senha (deixe em branco para não alterar)</label><input id="uPass" type="password" class="input"></div>
                <div class="form-row"><label>Nível (Role)</label>
                    <select id="uRole" class="input">
                        <option value="visitante" ${user.role === 'visitante' ? 'selected' : ''}>Visitante</option>
                        <option value="admin" ${user.role === 'admin' ? 'selected' : ''}>Admin</option>
                    </select>
                </div>
                <div class="footer-actions">
                    <button type="submit" class="btn btn-primary">Salvar</button>
                    <button type="button" class="btn btn-ghost" onclick="location.hash='#users';render()">Cancelar</button>
                </div>
            </form>
        </div>
    `;

    const form = document.getElementById('editUserForm');
    form.onsubmit = async (e) => {
        e.preventDefault();
        const payload = {
            name: document.getElementById('uName').value,
            username: document.getElementById('uUser').value,
            email: document.getElementById('uEmail').value,
            password: document.getElementById('uPass').value || undefined,
            role: document.getElementById('uRole').value
        };
        try {
            await updateUser(user.id, payload);
            alert('Usuário atualizado com sucesso!');
            location.hash = '#users';
            render();
        } catch (e) {
            alert('Erro ao atualizar usuário: ' + e.message);
        }
    };
}

/**
 * Renderiza e associa a lógica ao formulário de edição de um setor.
 * @param {object} setor - O objeto do setor a ser editado.
 */
function renderEditSetor(setor) {
    const app = document.getElementById('app');
    app.innerHTML = `
        <div class="card">
            <h2>Editar Setor</h2>
            <form id="editSetorForm">
                <div class="form-row"><label>Nome do Setor</label><input id="sName" class="input" value="${setor.name}" required></div>
                <div class="form-row"><label>Vagas Disponíveis</label><input id="sVagas" type="number" min="0" max="150" class="input" value="${setor.vagas}" required></div>
                <div class="footer-actions">
                    <button type="submit" class="btn btn-primary">Salvar</button>
                    <button type="button" class="btn btn-ghost" onclick="location.hash='#setores';render()">Cancelar</button>
                </div>
            </form>
        </div>
    `;

    const form = document.getElementById('editSetorForm');
    form.onsubmit = async (e) => {
        e.preventDefault();
        const payload = {
            name: document.getElementById('sName').value,
            vagas: Number(document.getElementById('sVagas').value)
        };
        try {
            await updateSetor(setor.id, payload);
            alert('Setor atualizado com sucesso!');
            location.hash = '#setores';
            render();
        } catch (e) {
            alert('Erro ao atualizar setor: ' + e.message);
        }
    };
}

// --- NOVA FUNÇÃO PARA RENDERIZAR A NAVEGAÇÃO ---
/**
 * Renderiza os menus de navegação com base no status de login e no nível do usuário.
 */
function renderNavigation() {
    const nav = document.getElementById('mainNav');
    if (!nav) return;

    const isAdmin = currentUser && currentUser.role === 'admin';
    let navHtml = '';

    // Botão Início (sempre visível)
    navHtml += `<button data-route="home">Início</button>`;

    if (isAdmin) {
        // Menu Gestão
        navHtml += `
            <div class="nav-item">
                <button class="nav-toggle">Gestão</button>
                <div class="dropdown-menu">
                    <button data-route="users">Usuários</button>
                    <button data-route="falecidos">Falecidos</button>
                    <button data-route="setores">Setores</button>
                    <button data-route="setor-vagas">Vagas por Setor</button>
                </div>
            </div>
        `;
        // Menu Comercial
        navHtml += `
            <div class="nav-item">
                <button class="nav-toggle">Comercial</button>
                <div class="dropdown-menu">
                    <button data-route="financeiro">Financeiro</button>
                    <button data-route="catalog">Catálogo</button>
                    <button data-route="pedidos">Pedidos</button>
                </div>
            </div>
        `;
    } else if (currentUser) {
        // Menu para Visitantes
        navHtml += `<button data-route="falecidos">Meus Falecidos</button>`;
        navHtml += `<button data-route="catalog">Catálogo</button>`;
        navHtml += `<button data-route="pedidos">Meus Pedidos</button>`;
    } else {
        // Menu para não logados
        navHtml += `<button data-route="catalog">Catálogo</button>`;
    }

    nav.innerHTML = navHtml;
    bindNavigation(); // Associa os eventos aos novos botões
}


/** Renderiza o cabeçalho, incluindo os controles de usuário (login/logout, perfil). */
function renderHeader(){
    const c = document.getElementById('userControls'); if(!c) return;
    c.innerHTML = '';
    
    const isAdmin = currentUser && currentUser.role === 'admin';

    if(!currentUser){
        const btn = document.createElement('button'); btn.className='btn btn-ghost'; btn.textContent='Entrar'; btn.onclick = ()=>{ location.hash = 'login'; render(); }; c.appendChild(btn);
    } else {
        const name = document.createElement('div'); name.className='user-name'; name.textContent = currentUser.name || currentUser.username || 'Usuário'; c.appendChild(name);
        
        // Botão Meu Perfil
        const profileBtn = document.createElement('button'); 
        profileBtn.className='btn btn-ghost'; 
        profileBtn.textContent='Meu Perfil'; 
        profileBtn.onclick = ()=>{ location.hash = '#profile'; render(); }; 
        c.appendChild(profileBtn);
        
        const out = document.createElement('button'); out.className='btn btn-ghost'; out.textContent='Sair'; out.onclick = logoutUser; c.appendChild(out);
    }
    renderNavigation(); // Renderiza a navegação principal
}

/**
 * Roteador principal da aplicação.
 * Lê o hash da URL, renderiza a view correspondente e associa a lógica (bind).
 */
function render(){
    const app = document.getElementById('app'); if(!app) return;
    renderHeader();
    const routeParts = (location.hash.replace(/^#/,'') || 'home').split('/');
    const route = routeParts[0];
    const param = routeParts[1] || null;

    const isAdmin = currentUser && currentUser.role === 'admin';
    const isVisitor = currentUser && currentUser.role === 'visitante';
    // REMOVIDO 'new-user' da lista de rotas de gerenciamento
    const isManagementRoute = ['users', 'sectors', 'orders', 'finance', 'new-setor', 'new-falecido', 'new-financeiro', 'setor-vagas'].includes(route);

    // Bloquear rotas de gerenciamento para não administradores
    if (isManagementRoute && !isAdmin) {
        location.hash = '#access-denied';
        app.innerHTML = renderAccessDenied();
        return;
    }

    // Permitir visitantes acessarem apenas a rota de falecidos
    if (route === 'falecidos' || route === 'dead') {
        app.innerHTML = renderFalecidos();
        setTimeout(() => bindFalecidos(app), 0);
        return;
    }

    // ROTAS DE CRIAÇÃO (NOVAS)
    if(route === 'new-user'){ app.innerHTML = renderNewUser(); setTimeout(()=>bindNewUser(app),0); return; }
    if(route === 'new-setor'){ app.innerHTML = renderNewSetor(); setTimeout(()=>bindNewSetor(app),0); return; }
    if(route === 'new-falecido'){ app.innerHTML = renderNewFalecido(); setTimeout(()=>bindNewFalecido(app),0); return; }
    if(route === 'new-financeiro'){ app.innerHTML = renderNewFinanceiro(); setTimeout(()=>bindNewFinanceiro(app),0); return; }
    
    // ROTAS DE VISUALIZAÇÃO/LISTAGEM (GERENCIAMENTO)
    if(route === 'users'){ app.innerHTML = renderUsers(); setTimeout(()=>bindUsers(app),0); return; }
    if(route === 'setores' || route === 'sectors'){ app.innerHTML = renderSetores(); setTimeout(()=>bindSetores(app),0); return; }
    if(route === 'falecidos' || route === 'dead'){ app.innerHTML = renderFalecidos(); setTimeout(()=>bindFalecidos(app),0); return; }
    // Rota 'orders' agora usa a mesma view e bind de 'pedidos'
    if(route === 'orders' || route === 'pedidos'){ app.innerHTML = renderPedidos(); setTimeout(()=>bindPedidos(app),0); return; }
    if(route === 'financeiro' || route=== 'finance'){ app.innerHTML = renderFinanceiro(); setTimeout(()=>bindFinanceiro(app),0); return; }
    
    // --- NOVAS ROTAS DE RECUPERAÇÃO DE SENHA ---
    if(route === 'forgot-password'){ app.innerHTML = renderForgotPassword(); setTimeout(()=>bindForgotPassword(app),0); return; }
    if(route === 'reset-password'){ 
        if (!param) { location.hash = '#login'; render(); return; }
        app.innerHTML = renderResetPassword(param); 
        setTimeout(()=>bindResetPassword(app, param),0); 
        return; 
    }

    // --- NOVAS ROTAS DE PERFIL ---
    if(route === 'profile'){ if(!currentUser){ location.hash = '#login'; render(); return; } app.innerHTML = renderProfile(); setTimeout(()=>bindProfile(app),0); return; }
    if(route === 'edit-profile'){ if(!currentUser){ location.hash = '#login'; render(); return; } app.innerHTML = renderEditProfile(); setTimeout(()=>bindEditProfile(app),0); return; }

    // ROTAS DE COMPRA (ORIGINAIS)
    if(route === 'login'){ app.innerHTML = renderLogin(); setTimeout(()=>bindLogin(app),0); return; }
    if(route === 'catalog'){ app.innerHTML = renderCatalog(); setTimeout(()=>bindCatalog(app),0); return; }
    if(route === 'cart'){ app.innerHTML = renderCart(); setTimeout(()=>bindCart(app),0); return; }
    if(route === 'checkout'){ if(!currentUser){ location.hash = '#login'; render(); return; } app.innerHTML = renderCheckout(); setTimeout(()=>bindCheckout(app),0); return; }
    if(route === 'success'){ app.innerHTML = renderSuccess(); setTimeout(()=>{ const b = el('newCatalog'); if(b) b.onclick = ()=>{ location.hash = '#catalog'; render(); }; },0); return; }
    
    // Rota de acesso negado (fallback caso alguém navegue diretamente para #access-denied)
    if(route === 'access-denied'){ app.innerHTML = renderAccessDenied(); return; }

    // Rota para atribuir vaga
    if (location.hash.startsWith('#assign-vaga/')) {
        const falecidoId = location.hash.split('/')[1];
        app.innerHTML = renderAssignVaga(falecidoId);
        setTimeout(() => bindAssignVaga(app, falecidoId), 0);
        return;
    }

    // Rota de vagas por setor
    if (route === 'setor-vagas') {
        app.innerHTML = renderSetorVagas();
        setTimeout(() => bindSetorVagas(app), 0);
        return;
    }

    if (route === 'home') { app.innerHTML = renderHome(); return; }

    app.innerHTML = `<div class="card"><h2>Não encontrado</h2></div>`;
}

// --- NOVA FUNÇÃO PARA BIND DOS MENUS ---
/**
 * Associa eventos de clique aos botões de navegação e dropdowns.
 */
function bindNavigation() {
    const nav = document.getElementById('mainNav');
    if (!nav) return;

    // Eventos para os botões de rota
    nav.querySelectorAll('button[data-route]').forEach(b => {
        b.onclick = () => {
            location.hash = b.dataset.route;
            render();
            // Fecha o menu hambúrguer em mobile após clicar
            document.getElementById('mainNav').classList.remove('open');
        };
    });

    // Eventos para abrir/fechar dropdowns
    nav.querySelectorAll('.nav-toggle').forEach(toggle => {
        toggle.onclick = (e) => {
            e.stopPropagation();
            const parent = toggle.parentElement;
            // Fecha outros dropdowns abertos
            nav.querySelectorAll('.nav-item.open').forEach(openItem => {
                if (openItem !== parent) {
                    openItem.classList.remove('open');
                }
            });
            // Abre ou fecha o dropdown atual
            parent.classList.toggle('open');
        };
    });

    // Fecha dropdown se clicar fora
    document.addEventListener('click', (e) => {
        if (!nav.contains(e.target)) {
            nav.querySelectorAll('.nav-item.open').forEach(openItem => {
                openItem.classList.remove('open');
            });
        }
    });
}


// Initialize nav bindings
document.addEventListener('DOMContentLoaded', async () => {
    // --- INICIALIZA O MÓDULO DE CRIPTOGRAFIA ---
    try {
        await cryptoModule.initialize();
    } catch (e) {
        alert("Erro crítico de segurança: Não foi possível inicializar o módulo de criptografia. A aplicação não pode continuar.");
        document.body.innerHTML = '<div class="card" style="border-left: 5px solid red;"><h2>Erro Crítico</h2><p>Falha na inicialização do módulo de segurança. Verifique o console para mais detalhes.</p></div>';
        return;
    }

    // O bind da navegação agora é chamado dentro do renderHeader/renderNavigation
    
    // Bind para o menu hambúrguer
    const hamburger = document.getElementById('hamburgerMenu');
    const mainNav = document.getElementById('mainNav');
    if (hamburger && mainNav) {
        hamburger.onclick = () => {
            mainNav.classList.toggle('open');
        };
    }

    window.addEventListener('hashchange', render);
    render();
});

/**
 * Associa um plano/produto a um falecido.
 * @param {number} falecidoId - O ID do falecido.
 * @param {number} planoId - O ID do plano.
 */
async function associatePlanoToFalecido(falecidoId, planoId) {
    return api(`falecidos/${falecidoId}/associar-plano`, {
        method: 'POST',
        body: JSON.stringify({ plano_id: planoId })
    });
}

/**
 * Busca os planos associados a um falecido.
 * @param {number} falecidoId - O ID do falecido.
 */
async function getPlanosByFalecido(falecidoId) {
    return api(`falecidos/${falecidoId}/planos`);
}

// --- NOVA FUNÇÃO BINDCHECKOUT ---
/**
 * Associa a lógica ao formulário de checkout.
 * @param {HTMLElement} container - O elemento que contém a view.
 */
async function bindCheckout(container) {
    const form = container.querySelector('#checkoutForm');
    if (!form) return;

    // Preenche o nome e email do usuário logado, se disponível
    if (currentUser) {
        el('ckNome').value = currentUser.name || '';
        el('ckEmail').value = currentUser.email || '';
    }

    form.onsubmit = async (e) => {
        e.preventDefault();
        const cart = await getCart(currentUser?.id || null);
        if (!cart || cart.length === 0) {
            alert('Seu carrinho está vazio.');
            location.hash = '#catalog';
            render();
            return;
        }

        const catalog = await getCatalog();
        let total = 0;
        const itens = cart.map(item => {
            const prod = catalog.find(p => p.id == item.produto_id) || { preco: 0 };
            total += Number(prod.preco || 0) * item.quantidade;
            return {
                produto_id: item.produto_id,
                quantidade: item.quantidade,
                preco: prod.preco
            };
        });

        const payload = {
            user_id: currentUser?.id || null,
            nome: el('ckNome').value,
            cpf: el('ckCPF').value,
            email: el('ckEmail').value,
            telefone: el('ckTel').value,
            forma_pagamento: el('ckPagto').value,
            total: total,
            itens: itens
        };

        try {
            await createOrder(payload);
            await clearCart(currentUser?.id || null); // Limpa o carrinho após o pedido
            location.hash = '#success';
            render();
        } catch (err) {
            alert('Erro ao criar pedido: ' + err.message);
        }
    };

    const cancelBtn = el('cancelCheckout');
    if (cancelBtn) {
        cancelBtn.onclick = () => {
            location.hash = '#cart';
            render();
        };
    }
}
