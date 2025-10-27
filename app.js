/* app.js - Minimal API-first SPA
 * - Stores only session token in localStorage (cem_token)
 * - Frontend talks to backend via API_BASE
 */

const API_BASE = 'https://cemiterio-0elv.onrender.com/api';

let token = localStorage.getItem('cem_token') || null;
let currentUser = null; // populated after successful login

function authHeaders(){ return token ? { 'Authorization': 'Bearer ' + token } : {}; }

async function api(path, opts = {}){
    opts.headers = Object.assign({'Content-Type':'application/json'}, authHeaders(), opts.headers || {});
    const res = await fetch(API_BASE + '/' + path, opts);
    if(res.status === 204) return null;
    const j = await res.json().catch(()=>null);
    if(!res.ok) throw new Error((j && j.error) ? j.error : ('HTTP ' + res.status));
    return j;
}

// Função para verificar se o usuário está logado
function isUserLoggedIn() {
    return currentUser !== null;
}

// Função para verificar se o usuário é administrador
function isAdmin() {
    return currentUser && currentUser.role === 'admin';
}

// API helpers (Original)
const login = (username, password) => api('login', { method: 'POST', body: JSON.stringify({ username, password }) });
const getCatalog = () => api('catalogo');
const getCart = (userId = null) => {
    const url = new URL(API_BASE + '/carrinho');
    if(userId) url.searchParams.append('user_id', userId);
    return fetch(url.toString(), { headers: authHeaders() }).then(r => r.ok ? r.json() : Promise.reject(new Error('Erro ao buscar carrinho')));
};
const addCartItem = (produto_id, quantidade=1, user_id=null) => api('carrinho', { method: 'POST', body: JSON.stringify({ produto_id, quantidade, user_id }) });
const updateCartItem = (id, quantidade) => api('carrinho/' + id, { method: 'PUT', body: JSON.stringify({ quantidade }) });
const removeCartItem = (id) => fetch(API_BASE + '/carrinho/' + id, { method: 'DELETE', headers: authHeaders() }).then(r => r.ok ? r.json() : Promise.reject(new Error('Erro ao remover item')));
const clearCart = (userId=null) => fetch(API_BASE + '/carrinho?user_id=' + encodeURIComponent(userId || ''), { method: 'DELETE', headers: authHeaders() }).then(r => r.ok ? r.json() : Promise.reject(new Error('Erro ao limpar carrinho')));
const createOrder = (payload) => api('pedidos', { method: 'POST', body: JSON.stringify(payload) });

// API helpers (Gerenciamento)
const getUsers = () => api('usuarios');
const getSetores = () => api('setores');
const getFalecidos = () => api('falecidos');
const getOrders = () => api('pedidos');
const getFinanceiro = () => api('financeiro');

// NOVAS API helpers (CREATE)
const createUser = (payload) => api('usuarios', { method: 'POST', body: JSON.stringify(payload) });
const createSetor = (payload) => api('setores', { method: 'POST', body: JSON.stringify(payload) });
const createFalecido = (payload) => api('falecidos', { method: 'POST', body: JSON.stringify(payload) });
const createFinanceiro = (payload) => api('financeiro', { method: 'POST', body: JSON.stringify(payload) });
// --- FIM NOVAS API helpers (CREATE) ---

// NOVA API helper
const getSetorVagas = () => api('setores/vagas');

// NOVA API helper
const assignVaga = (falecidoId, payload) => api(`falecidos/${falecidoId}/atribuir-vaga`, { method: 'PUT', body: JSON.stringify(payload) });

// Adicione a função para excluir um falecido
async function deleteFalecido(falecidoId) {
    return api(`falecidos/${falecidoId}`, { method: 'DELETE' });
}

// Função para obter um único usuário
async function getUser(userId) {
    return api(`usuarios/${userId}`);
}

// Função para obter um único setor
async function getSetor(setorId) {
    return api(`setores/${setorId}`);
}

// Função para atualizar um usuário
async function updateUser(userId, payload) {
    return api(`usuarios/${userId}`, { method: 'PUT', body: JSON.stringify(payload) });
}

// Função para atualizar um setor
async function updateSetor(setorId, payload) {
    return api(`setores/${setorId}`, { method: 'PUT', body: JSON.stringify(payload) });
}

// Função para excluir um usuário
async function deleteUser(userId) {
    return api(`usuarios/${userId}`, { method: 'DELETE' });
}

// Função para excluir um setor
async function deleteSetor(setorId) {
    return api(`setores/${setorId}`, { method: 'DELETE' });
}

// Função para associar um falecido a um usuário
async function associateFalecidoToUser(falecidoId, userId) {
    return api(`falecidos/${falecidoId}/associar`, {
        method: 'POST',
        body: JSON.stringify({ user_id: userId })
    });
}

// Função para obter os falecidos associados a um usuário
async function getFalecidosByUser(userId) {
    return api(`usuarios/${userId}/falecidos`);
}

// Função para obter pedidos
async function getPedidos() {
    return api('pedidos');
}

// Função para aprovar ou rejeitar um pedido
async function updatePedidoAprovacao(pedidoId, aprovado) {
    return api(`pedidos/${pedidoId}/aprovar`, {
        method: 'PUT',
        body: JSON.stringify({ aprovado })
    });
}

// DOM helpers
const el = id => document.getElementById(id);

// ------------------------------------
// VIEWS (Templates HTML)
// ------------------------------------

// Views (Originals)
function renderLogin(){
    return `
        <div class="card">
            <h2>Entrar</h2>
            <div class="form-row"><label>Usuário</label><input id="loginUser" class="input"/></div>
            <div class="form-row"><label>Senha</label><input id="loginPass" type="password" class="input"/></div>
            <div class="footer-actions">
                <button id="goRegister" class="btn btn-ghost">Criar novo usuário</button>
                <button id="doLogin" class="btn btn-primary">Entrar</button>
            </div>
        </div>`;
}

function renderCatalog(){
    return `
        <div class="card">
            <h2>Catálogo</h2>
            <div id="catalogGrid" class="grid">Carregando...</div>
            <div class="footer-actions"><button id="goCart" class="btn btn-ghost">Ver carrinho</button></div>
        </div>`;
}

function renderCart(){
    return `
        <div class="card">
            <h2>Carrinho</h2>
            <div id="cartBody">Carregando...</div>
            <div class="footer-actions"><button id="goCheckout" class="btn btn-primary">Finalizar Pedido</button> <button id="backCatalog" class="btn btn-ghost">Continuar</button></div>
        </div>`;
}

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

function renderSuccess(){
    return `
        <div class="card">
            <h2>Pedido realizado</h2>
            <p>Pedido registrado com sucesso.</p>
            <button class="btn btn-primary" id="newCatalog">Novo pedido</button>
        </div>`;
}

function renderAccessDenied(){
     return `
        <div class="card" style="border-left: 5px solid red;">
            <h2>Acesso Negado</h2>
            <p>Você não tem permissão para visualizar esta página.</p>
            <p><a href="#catalog" onclick="render()">Voltar ao Catálogo</a></p>
        </div>`;
}

// Views (Gerenciamento)
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

function renderOrders(){
    return `
        <div class="card">
            <h2>Pedidos Realizados</h2>
            <div id="ordersList">Carregando...</div>
        </div>`;
}

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
function renderNewUser(){
    return `
        <div class="card">
            <h2>Novo Usuário</h2>
            <form id="newUserForm">
                <div class="form-row"><label>Nome</label><input id="uName" class="input" required></div>
                <div class="form-row"><label>Usuário (Login)</label><input id="uUser" class="input" required></div>
                <div class="form-row"><label>Email</label><input id="uEmail" type="email" class="input"></div>
                <div class="form-row"><label>Senha</label><input id="uPass" type="password" class="input" required></div>
                <div class="form-row"><label>Nível (Role)</label>
                    <select id="uRole" class="input">
                        <option value="visitante">Visitante</option>
                        <option value="admin">admin</option>
                    </select>
                </div>
                <div class="footer-actions">
                    <button type="submit" class="btn btn-primary">Salvar</button>
                    <button type="button" class="btn btn-ghost" onclick="location.hash='#users';render()">Cancelar</button>
                </div>
            </form>
        </div>`;
}

function renderNewSetor(){
    return `
        <div class="card">
            <h2>Novo Setor</h2>
            <form id="newSetorForm">
                <div class="form-row"><label>Nome do Setor</label><input id="sName" class="input" required></div>
                <div class="form-row"><label>Vagas Disponíveis</label><input id="sVagas" type="number" min="0" class="input" required></div>
                <div class="footer-actions">
                    <button type="submit" class="btn btn-primary">Salvar</button>
                    <button type="button" class="btn btn-ghost" onclick="location.hash='#setores';render()">Cancelar</button>
                </div>
            </form>
        </div>`;
}

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
function renderSetorVagas() {
    return `
        <div class="card">
            <h2>Vagas por Setor</h2>
            <div id="setoresButtons">Carregando setores...</div>
            <div id="setorVagasList"></div>
        </div>`;
}

// NOVA VIEW
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

// Nova função para renderizar a tela inicial (home)
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

// Função para renderizar a lista de pedidos
function renderPedidos() {
    return `
        <div class="card">
            <h2>Pedidos Realizados</h2>
            <div id="pedidosList">Carregando...</div>
        </div>`;
}

// ------------------------------------
// BINDS (Lógica e API Calls)
// ------------------------------------

// Binds (Originais)
async function bindLogin(container){
    const btn = el('doLogin');
    if(!btn) return;
    btn.onclick = async () => {
        const u = el('loginUser').value.trim();
        const p = el('loginPass').value;
        if(!u || !p){ alert('Informe usuário e senha'); return; }
        try{
            const res = await login(u,p);
            token = res.token;
            currentUser = res.user || null;
            localStorage.setItem('cem_token', token);
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

async function bindCheckout(container){
    const summary = container.querySelector('#checkoutSummary');
    try{
        const cart = await getCart(currentUser?.id||null);
        if(!cart || !cart.length){ location.hash = '#catalog'; render(); return; }
        const catalog = await getCatalog();
        const itens = cart.map(i => { const p = catalog.find(c=>c.id==i.produto_id)||{}; return { produto_id: i.produto_id, quantidade: i.quantidade, preco: Number(p.preco||0) }; });
        const total = itens.reduce((s,it)=> s + (it.preco * it.quantidade), 0);
        summary.innerHTML = `<h3>Total: R$ ${total.toFixed(2)}</h3>`;
    }catch(e){ summary.innerHTML = '<p style="color:red">Erro ao calcular total</p>'; }

    const form = container.querySelector('#checkoutForm'); if(!form) return;
    form.onsubmit = async (e) => {
        e.preventDefault();
        try{
            const cart = await getCart(currentUser?.id||null);
            const catalog = await getCatalog();
            const itens = cart.map(i => { const p = catalog.find(c=>c.id==i.produto_id)||{}; return { produto_id: i.produto_id, quantidade: i.quantidade, preco: Number(p.preco||0) }; });
            const total = itens.reduce((s,it)=> s + (it.preco * it.quantidade), 0);
            const payload = {
                user_id: currentUser?.id || null,
                nome: el('ckNome').value,
                cpf: el('ckCPF').value,
                email: el('ckEmail').value,
                telefone: el('ckTel').value,
                forma_pagamento: el('ckPagto').value,
                total,
                itens
            };
            await createOrder(payload);
            await clearCart(currentUser?.id||null);
            location.hash = '#success'; render();
        }catch(e){ alert('Erro ao enviar pedido: '+e.message); }
    };
    const cancel = el('cancelCheckout'); if(cancel) cancel.onclick = ()=>{ location.hash = '#cart'; render(); };
}

// Binds (Gerenciamento)
async function bindUsers(container){
    const list = container.querySelector('#usersList');
    if(!list) return;
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

async function bindFalecidos(container) {
    const list = container.querySelector('#falecidosList');
    if (!list) return;

    // Bind para o botão "Adicionar Falecido" (deve ser feito aqui, fora do try/catch da lista)
    if (currentUser?.role === 'admin') {
        const newBtn = container.querySelector('button[data-route="new-falecido"]');
        if (newBtn) {
            newBtn.onclick = () => { location.hash = '#new-falecido'; render(); };
        }
    }

    // Verifique se o usuário está logado
    if (!isUserLoggedIn()) {
        list.innerHTML = '<p style="color:red">Você precisa estar logado para visualizar os falecidos.</p>';
        return;
    }

    try {
        const falecidos = await getFalecidos();
        if (!falecidos || falecidos.length === 0) {
            list.innerHTML = '<p>Nenhum falecido encontrado.</p>';
            return;
        }

        let html = falecidos.map(f => `
            <div class="list-item falecido-item">
                <div>
                    <strong>${f.name}</strong> (Nasc: ${f.anoNascimento} - Morte: ${f.anoMorte})<br>
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
            // Adiciona o bind para o botão "Adicionar Falecido"
            const newBtn = container.querySelector('button[data-route="new-falecido"]');
            if (newBtn) {
                newBtn.onclick = () => { location.hash = '#new-falecido'; render(); };
            }

            list.querySelectorAll('[data-edit]').forEach(btn => {
                btn.onclick = () => {
                    const falecidoId = btn.dataset.edit;
                    renderEditFalecido(falecidoId);
                };
            });

            list.querySelectorAll('[data-delete]').forEach(btn => {
                btn.onclick = async () => {
                    const falecidoId = btn.dataset.delete;
                    if (confirm('Tem certeza de que deseja excluir este registro?')) {
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
        list.innerHTML = `<p style="color:red">Erro ao carregar falecidos: ${e.message}</p>`;
    }
}

async function bindPedidos(container) {
    const list = container.querySelector('#pedidosList');
    if (!list) return;

    // Verifique se o usuário está logado
    if (!isUserLoggedIn()) {
        list.innerHTML = '<p style="color:red">Você precisa estar logado para visualizar os pedidos.</p>';
        return;
    }

    try {
        const pedidos = await getPedidos();
        if (!pedidos || pedidos.length === 0) {
            list.innerHTML = '<p>Nenhum pedido encontrado.</p>';
            return;
        }

        let html = pedidos.map(p => {
            let statusAprovacao = 'Pendente';
            if (p.aprovado === 1) {
                statusAprovacao = 'Aprovado';
            } else if (p.aprovado === 0) {
                statusAprovacao = 'Rejeitado';
            }

            return `
            <div class="list-item pedido-item">
                <div>
                    <strong>Pedido #${p.id}</strong> (Total: R$ ${Number(p.total).toFixed(2)})<br>
                    <small>Status: ${p.status} | Cliente: ${p.nome} | Data: ${new Date(p.created_at).toLocaleDateString()}</small><br>
                    <small>Aprovação: ${statusAprovacao}</small><br>
                    ${currentUser?.role === 'admin' && p.aprovado === null ? `
                        <div class="actions">
                            <button class="btn btn-primary" data-aprovar="${p.id}">Aprovar</button>
                            <button class="btn btn-danger" data-rejeitar="${p.id}">Rejeitar</button>
                        </div>
                    ` : ''}
                </div>
            </div>
        `}).join('');
        list.innerHTML = html;

        if (currentUser?.role === 'admin') {
            const handleUpdate = async (pedidoId, isApproved, successMessage, errorMessage) => {
                try {
                    await updatePedidoAprovacao(pedidoId, isApproved);
                    alert(successMessage);
                    // Recarrega a view para refletir a mudança
                    const currentHash = location.hash;
                    location.hash = '';
                    location.hash = currentHash;
                    render();
                } catch (e) {
                    alert(`${errorMessage}: ${e.message}`);
                }
            };

            list.querySelectorAll('[data-aprovar]').forEach(btn => {
                btn.onclick = () => handleUpdate(btn.dataset.aprovar, true, 'Pedido aprovado com sucesso!', 'Erro ao aprovar pedido');
            });

            list.querySelectorAll('[data-rejeitar]').forEach(btn => {
                btn.onclick = () => handleUpdate(btn.dataset.rejeitar, false, 'Pedido rejeitado com sucesso!', 'Erro ao rejeitar pedido');
            });
        }
    } catch (e) {
        list.innerHTML = `<p style="color:red">Erro ao carregar pedidos: ${e.message}</p>`;
    }
}

// Nova função para renderizar o formulário de edição de falecidos
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

async function bindOrders(container){
    const list = container.querySelector('#ordersList');
    if(!list) return;
    try{
        const orders = await getOrders();
        let html = orders.map(o => `
            <div class="list-item order-item">
                <div>
                    <strong>Pedido #${o.id}</strong> (Total: R$ ${Number(o.total).toFixed(2)})<br>
                    <small>Status: ${o.status} | Cliente: ${o.nome} | Data: ${new Date(o.created_at).toLocaleDateString()}</small>
                </div>
                <div>
                    <button class="btn btn-ghost" data-view="${o.id}">Ver Detalhes</button>
                </div>
            </div>
        `).join('');
        list.innerHTML = html;
    }catch(e){
        list.innerHTML = '<p style="color:red">Erro ao carregar pedidos</p>';
    }
}

async function bindFinanceiro(container) {
    const list = container.querySelector('#financeiroList');
    if (!list) return;
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
                        <option value="pendente" ${financeiro.status === 'pendente' ? 'selected' : ''}>Pendente</option>
                        <option value="pago" ${financeiro.status === 'pago' ? 'selected' : ''}>Pago</option>
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

// Funções auxiliares para financeiro
async function getFinanceiroById(id) {
    return api(`financeiro/${id}`);
}

async function updateFinanceiro(id, payload) {
    return api(`financeiro/${id}`, { method: 'PUT', body: JSON.stringify(payload) });
}

async function deleteFinanceiro(id) {
    return api(`financeiro/${id}`, { method: 'DELETE' });
}

// NOVOS BINDS (Lógica de Submissão de Formulário)
async function bindNewUser(container){
    const form = container.querySelector('#newUserForm');
    if(!form) return;
    form.onsubmit = async (e) => {
        e.preventDefault();
        const payload = {
            name: el('uName').value,
            username: el('uUser').value,
            email: el('uEmail').value,
            password: el('uPass').value,
            role: el('uRole').value
        };
        try{
            await createUser(payload);
            alert('Usuário criado com sucesso!');
            location.hash = '#users'; 
            render();
        }catch(e){
            alert('Erro ao criar usuário: ' + e.message);
        }
    };
}

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

// Função para carregar vagas de um setor específico
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

// Função para renderizar o formulário de edição de usuários
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

// Função para renderizar o formulário de edição de setores
function renderEditSetor(setor) {
    const app = document.getElementById('app');
    app.innerHTML = `
        <div class="card">
            <h2>Editar Setor</h2>
            <form id="editSetorForm">
                <div class="form-row"><label>Nome do Setor</label><input id="sName" class="input" value="${setor.name}" required></div>
                <div class="form-row"><label>Vagas Disponíveis</label><input id="sVagas" type="number" min="0" class="input" value="${setor.vagas}" required></div>
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

// Header (User Controls)
function renderHeader(){
    const c = document.getElementById('userControls'); if(!c) return;
    c.innerHTML = '';
    
    const isAdmin = currentUser && currentUser.role === 'admin';

    if(!currentUser){
        const btn = document.createElement('button'); btn.className='btn btn-ghost'; btn.textContent='Entrar'; btn.onclick = ()=>{ location.hash = 'login'; render(); }; c.appendChild(btn);
    } else {
        const name = document.createElement('div'); name.className='user-name'; name.textContent = currentUser.name || currentUser.username || 'Usuário'; c.appendChild(name);
        
        if (isAdmin) {
             const adminBtn = document.createElement('button'); 
             adminBtn.className='btn btn-ghost'; 
             adminBtn.textContent='Admin'; 
             adminBtn.onclick = ()=>{ location.hash = '#users'; render(); }; 
             c.appendChild(adminBtn);
        }

        const out = document.createElement('button'); out.className='btn btn-ghost'; out.textContent='Sair'; out.onclick = ()=>{ token=null; localStorage.removeItem('cem_token'); currentUser=null; location.hash = '#catalog'; render(); }; c.appendChild(out);
    }
}

// Router - ATUALIZADO com Novas Rotas de Criação (new-X)
function render(){
    const app = document.getElementById('app'); if(!app) return;
    renderHeader();
    const route = (location.hash.replace(/^#/,'') || 'home').split('/')[0];

    const isAdmin = currentUser && currentUser.role === 'admin';
    const isVisitor = currentUser && currentUser.role === 'visitante';
    const isManagementRoute = ['users', 'sectors', 'orders', 'finance', 'new-setor', 'new-falecido', 'new-financeiro', 'setor-vagas'].includes(route);

    // Bloquear rotas de gerenciamento para visitantes
    if (isManagementRoute && !isAdmin) {
        location.hash = '#access-denied';
        app.innerHTML = renderAccessDenied();
        return;
    }

    // // Permitir visitantes acessarem apenas a rota de falecidos
    // if (route === 'falecidos' || route === 'dead') {
    //     app.innerHTML = renderFalecidos();
    //     setTimeout(() => bindFalecidos(app), 0);
    //     return;
    // }

    // ROTAS DE CRIAÇÃO (NOVAS)
    if(route === 'new-user'){ app.innerHTML = renderNewUser(); setTimeout(()=>bindNewUser(app),0); return; }
    if(route === 'new-setor'){ app.innerHTML = renderNewSetor(); setTimeout(()=>bindNewSetor(app),0); return; }
    if(route === 'new-falecido'){ app.innerHTML = renderNewFalecido(); setTimeout(()=>bindNewFalecido(app),0); return; }
    if(route === 'new-financeiro'){ app.innerHTML = renderNewFinanceiro(); setTimeout(()=>bindNewFinanceiro(app),0); return; }
    
    // ROTAS DE VISUALIZAÇÃO/LISTAGEM (GERENCIAMENTO)
    if(route === 'users'){ app.innerHTML = renderUsers(); setTimeout(()=>bindUsers(app),0); return; }
    if(route === 'setores' || route === 'sectors'){ app.innerHTML = renderSetores(); setTimeout(()=>bindSetores(app),0); return; }
    if(route === 'falecidos' || route === 'dead'){ app.innerHTML = renderFalecidos(); setTimeout(()=>bindFalecidos(app),0); return; }
    if(route === 'orders' || route === 'pedidos'){ app.innerHTML = renderPedidos(); setTimeout(()=>bindPedidos(app),0); return; }
    if(route === 'financeiro' || route=== 'finance'){ app.innerHTML = renderFinanceiro(); setTimeout(()=>bindFinanceiro(app),0); return; }
    if(route === 'pedidos'){ app.innerHTML = renderPedidos(); setTimeout(()=>bindPedidos(app),0); return; }
    
    // ROTAS DE COMPRA (ORIGINAIS)
    if(route === 'login'){ app.innerHTML = renderLogin(); setTimeout(()=>bindLogin(app),0); return; }
    if(route === 'catalog'){ app.innerHTML = renderCatalog(); setTimeout(()=>bindCatalog(app),0); return; }
    if(route === 'cart'){ app.innerHTML = renderCart(); setTimeout(()=>bindCart(app),0); return; }
    if(route === 'checkout'){ if(!currentUser){ location.hash = '#login'; return; } app.innerHTML = renderCheckout(); setTimeout(()=>bindCheckout(app),0); return; }
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

// Initialize nav bindings
document.addEventListener('DOMContentLoaded', () => {
    const nav = document.getElementById('mainNav');
    

    document.querySelectorAll('nav button[data-route]').forEach(b => {
        b.onclick = () => {
            location.hash = b.dataset.route;
            render();
        };
    });

    window.addEventListener('hashchange', render);
    render();
});

// Função para associar um plano a um falecido
async function associatePlanoToFalecido(falecidoId, planoId) {
    return api(`falecidos/${falecidoId}/associar-plano`, {
        method: 'POST',
        body: JSON.stringify({ plano_id: planoId })
    });
}

// Função para obter os planos associados a um falecido
async function getPlanosByFalecido(falecidoId) {
    return api(`falecidos/${falecidoId}/planos`);
}

/**
 * Função para aplicar hash e salt ao CPF antes de enviá-lo ao backend.
 * @param {string} cpf - O CPF a ser protegido.
 * @returns {string} - O CPF protegido com hash e salt.
 */
function hashCPF(cpf) {
    const salt = CryptoJS.lib.WordArray.random(16); // Gera um salt aleatório
    const hash = CryptoJS.PBKDF2(cpf, salt, { keySize: 256 / 32, iterations: 1000 });
    return `${salt.toString(CryptoJS.enc.Hex)}:${hash.toString(CryptoJS.enc.Hex)}`;
}
