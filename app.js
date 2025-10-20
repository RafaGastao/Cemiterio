/* app.js - Minimal API-first SPA
 * - Stores only session token in localStorage (cem_token)
 * - Frontend talks to backend via API_BASE
 */

const API_BASE = 'http://localhost:5000/api';

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
            <div class="footer-actions"><button id="doLogin" class="btn btn-primary">Entrar</button></div>
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
            <div class="footer-actions">
                <button class="btn btn-primary" data-route="new-falecido">Adicionar Falecido</button>
            </div>
        </div>`;
}

function renderOrders(){
    return `
        <div class="card">
            <h2>Pedidos Realizados</h2>
            <div id="ordersList">Carregando...</div>
        </div>`;
}

function renderFinanceiro(){
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
                <div class="form-row"><label>Setor</label><input id="fSetor" class="input" placeholder="ID ou Nome do Setor" required></div>
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
// --- FIM NOVAS VIEWS (CRIAÇÃO) ---

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
                    </div>
            </div>
        `).join('');
        list.innerHTML = html;
        // Adicionar binding para o botão 'Novo Usuário'
        container.querySelector('button[data-route="new-user"]').onclick = () => { location.hash = '#new-user'; render(); };
        // Bindings para botões de ação (Editar/Deletar) iriam aqui.
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
                </div>
            </div>
        `).join('');
        list.innerHTML = html;
        // Adicionar binding para o botão 'Novo Setor'
        container.querySelector('button[data-route="new-setor"]').onclick = () => { location.hash = '#new-setor'; render(); };
    }catch(e){
        list.innerHTML = '<p style="color:red">Erro ao carregar setores</p>';
    }
}

async function bindFalecidos(container){
    const list = container.querySelector('#falecidosList');
    if(!list) return;
    try{
        const falecidos = await getFalecidos();
        let html = falecidos.map(f => `
            <div class="list-item falecido-item">
                <div>
                    <strong>${f.name}</strong> (Nasc: ${f.anoNascimento} - Morte: ${f.anoMorte})<br>
                    <small>Setor: ${f.setor}</small>
                </div>
                <div>
                    <button class="btn btn-ghost" data-edit="${f.id}">Editar</button>
                </div>
            </div>
        `).join('');
        list.innerHTML = html;
        // Adicionar binding para o botão 'Adicionar Falecido'
        container.querySelector('button[data-route="new-falecido"]').onclick = () => { location.hash = '#new-falecido'; render(); };
    }catch(e){
        list.innerHTML = '<p style="color:red">Erro ao carregar falecidos</p>';
    }
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

async function bindFinanceiro(container){
    const list = container.querySelector('#financeiroList');
    if(!list) return;
    try{
        const items = await getFinanceiro();
        let html = items.map(i => `
            <div class="list-item financeiro-item">
                <div>
                    <strong>${i.descricao}</strong> (${i.tipo})<br>
                    <small>Valor: R$ ${Number(i.valor).toFixed(2)} | Data: ${i.data}</small>
                </div>
                <div>
                    <button class="btn btn-ghost" data-edit="${i.id}">Editar</button>
                </div>
            </div>
        `).join('');
        list.innerHTML = html;
        // Adicionar binding para o botão 'Novo Registro'
        container.querySelector('button[data-route="new-financeiro"]').onclick = () => { location.hash = '#new-financeiro'; render(); };
    }catch(e){
        list.innerHTML = '<p style="color:red">Erro ao carregar financeiro</p>';
    }
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

async function bindNewFalecido(container){
    const form = container.querySelector('#newFalecidoForm');
    if(!form) return;
    form.onsubmit = async (e) => {
        e.preventDefault();
        const payload = {
            name: el('fName').value,
            anoNascimento: Number(el('fNascimento').value),
            anoMorte: Number(el('fMorte').value),
            setor: el('fSetor').value // Assumindo que este campo aceita o ID ou nome do setor
        };
        try{
            await createFalecido(payload);
            alert('Falecido registrado com sucesso!');
            location.hash = '#falecidos'; 
            render();
        }catch(e){
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
    const route = (location.hash.replace(/^#/,'') || 'catalog').split('/')[0];

    const isAdmin = currentUser && currentUser.role === 'admin';
    const isManagementRoute = ['users', 'setores', 'sectors', 'falecidos', 'deceased', 'orders', 'financeiro', 'new-user', 'new-setor', 'new-falecido', 'new-financeiro'].includes(route);

    if (isManagementRoute && !isAdmin) {
        location.hash = '#access-denied'; 
        app.innerHTML = renderAccessDenied();
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
    if(route === 'orders'){ app.innerHTML = renderOrders(); setTimeout(()=>bindOrders(app),0); return; }
    if(route === 'financeiro' || route=== 'finance'){ app.innerHTML = renderFinanceiro(); setTimeout(()=>bindFinanceiro(app),0); return; }
    
    // ROTAS DE COMPRA (ORIGINAIS)
    if(route === 'login'){ app.innerHTML = renderLogin(); setTimeout(()=>bindLogin(app),0); return; }
    if(route === 'catalog'){ app.innerHTML = renderCatalog(); setTimeout(()=>bindCatalog(app),0); return; }
    if(route === 'cart'){ app.innerHTML = renderCart(); setTimeout(()=>bindCart(app),0); return; }
    if(route === 'checkout'){ if(!currentUser){ location.hash = '#login'; return; } app.innerHTML = renderCheckout(); setTimeout(()=>bindCheckout(app),0); return; }
    if(route === 'success'){ app.innerHTML = renderSuccess(); setTimeout(()=>{ const b = el('newCatalog'); if(b) b.onclick = ()=>{ location.hash = '#catalog'; render(); }; },0); return; }
    
    // Rota de acesso negado (fallback caso alguém navegue diretamente para #access-denied)
    if(route === 'access-denied'){ app.innerHTML = renderAccessDenied(); return; }

    app.innerHTML = `<div class="card"><h2>Não encontrado</h2></div>`;
}

// Initialize nav bindings
document.addEventListener('DOMContentLoaded', ()=>{
    document.querySelectorAll('nav button[data-route]').forEach(b=> b.onclick = ()=>{ location.hash = b.dataset.route; render(); });
    window.addEventListener('hashchange', render);
    render();
});
