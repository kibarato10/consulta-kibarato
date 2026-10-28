// Funções compartilhadas entre a página do cliente (index.html) e a do lojista (gerar.html).
// Os dados de cada cliente ficam criptografados com uma chave derivada do CPF e da data de nascimento:
// quem abre o arquivo dados.json não consegue ler nomes, CPFs ou valores.

const ITERACOES = 600000;

function soDigitos(s) {
  return String(s || '').replace(/\D/g, '');
}

function cpfValido(cpf) {
  cpf = soDigitos(cpf);
  if (cpf.length !== 11 || /^(\d)\1{10}$/.test(cpf)) return false;
  for (let t = 9; t < 11; t++) {
    let soma = 0;
    for (let i = 0; i < t; i++) soma += Number(cpf[i]) * (t + 1 - i);
    const dv = ((soma * 10) % 11) % 10;
    if (dv !== Number(cpf[t])) return false;
  }
  return true;
}

function b64(bytes) {
  let s = '';
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s);
}

function deB64(str) {
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

function hex(bytes) {
  return Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, '0')).join('');
}

// "d/m/aaaa", "dd/mm/aaaa" ou Date -> "ddmmaaaa"; vazio se não for uma data válida.
function nascDigitos(v) {
  if (v instanceof Date) v = String(v.getDate()).padStart(2, '0') + '/' + String(v.getMonth() + 1).padStart(2, '0') + '/' + v.getFullYear();
  const m = /^(\d{1,2})\/(\d{1,2})\/(\d{4})/.exec(String(v || '').trim());
  if (!m) return '';
  const d = new Date(Number(m[3]), Number(m[2]) - 1, Number(m[1]));
  if (d.getDate() !== Number(m[1]) || d.getMonth() !== Number(m[2]) - 1 || d.getFullYear() < 1900 || d > new Date()) return '';
  return m[1].padStart(2, '0') + m[2].padStart(2, '0') + m[3];
}

// A partir do CPF, da data de nascimento e do "sal" do arquivo, gera o identificador do registro e a chave AES.
async function derivar(cpf, nasc, sal) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(soDigitos(cpf) + nascDigitos(nasc)), 'PBKDF2', false, ['deriveBits']);
  const bits = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: sal, iterations: ITERACOES }, base, 512));
  const chave = await crypto.subtle.importKey('raw', bits.slice(0, 32), 'AES-GCM', false, ['encrypt', 'decrypt']);
  return { id: hex(bits.slice(32, 44)), chave };
}

async function cifrar(chave, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, chave, new TextEncoder().encode(JSON.stringify(obj)));
  return { iv: b64(iv), ct: b64(ct) };
}

async function decifrar(chave, reg) {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: deB64(reg.iv) }, chave, deB64(reg.ct));
  return JSON.parse(new TextDecoder().decode(pt));
}

function moeda(v) {
  return Number(v).toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' });
}

// "dd/mm/aaaa" -> Date (meia-noite local)
function data(s) {
  const m = /^(\d{2})\/(\d{2})\/(\d{2,4})$/.exec(String(s || '').trim());
  if (!m) return null;
  const ano = m[3].length === 2 ? 2000 + Number(m[3]) : Number(m[3]);
  return new Date(ano, Number(m[2]) - 1, Number(m[1]));
}
