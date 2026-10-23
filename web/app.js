/**
 * app.js — Controlador do Terminal Web e Integração WebAssembly (freestanding)
 *
 * Comunicação direta com a memória linear do WebAssembly sem alocações dinâmicas
 * ou dependências externas de runtime.
 */

class RsaWebTerminal {
  constructor() {
    this.wasm = null;
    this.memory = null;
    this.encoder = new TextEncoder();
    this.decoder = new TextDecoder();

    this.history = [];
    this.historyIndex = -1;

    this.cachedKeys = {
      pubPem: '',
      privPem: '',
      inspectData: null,
      lastCipher: '',
      lastPlain: '',
    };

    this.initDOMElements();
    this.initEventListeners();
    this.loadWasm();
  }

  initDOMElements() {
    this.terminalOutput = document.getElementById('terminal-output');
    this.terminalInput = document.getElementById('terminal-input');
    this.wasmStatus = document.getElementById('wasm-status');
    this.metricKeygenTime = document.getElementById('metric-keygen-time');

    // Elementos do painel de fórmulas
    this.dispP = document.getElementById('disp-p');
    this.dispQ = document.getElementById('disp-q');
    this.dispN = document.getElementById('disp-n');
    this.dispD = document.getElementById('disp-d');
    this.dispDp = document.getElementById('disp-dp');
    this.dispDq = document.getElementById('disp-dq');
    this.dispQinv = document.getElementById('disp-qinv');
    this.dispCipher = document.getElementById('disp-cipher');

    // Botões
    this.btnKeygen = document.getElementById('btn-demo-keygen');
    this.btnEncrypt = document.getElementById('btn-demo-encrypt');
    this.btnDecrypt = document.getElementById('btn-demo-decrypt');
    this.btnClear = document.getElementById('btn-clear');
  }

  initEventListeners() {
    this.terminalInput.addEventListener('keydown', (e) => this.handleInputKeydown(e));
    this.btnKeygen.addEventListener('click', () => this.executeKeygen());
    this.btnEncrypt.addEventListener('click', () => this.executeEncrypt('Mensagem Secreta Demonstrativa (OAEP-SHA256)'));
    this.btnDecrypt.addEventListener('click', () => this.executeDecrypt());
    this.btnClear.addEventListener('click', () => this.clearTerminal());

    // Foca o input ao clicar no corpo do terminal
    document.getElementById('terminal-body').addEventListener('click', () => {
      this.terminalInput.focus();
    });
  }

  async loadWasm() {
    try {
      const response = await fetch('rsa.wasm');
      const { instance } = await WebAssembly.instantiateStreaming(response, {});
      this.wasm = instance.exports;
      this.memory = instance.exports.memory;

      this.wasmStatus.textContent = 'WASM Ativo';
      this.wasmStatus.style.borderColor = '#10b981';
      this.wasmStatus.style.color = '#10b981';

      this.printLine('✓ Módulo WebAssembly RSA-2048 carregado com sucesso.', 'term-green');
      this.printLine('Pronto para operações criptográficas de alta performance.\n', 'term-muted');
    } catch (err) {
      this.wasmStatus.textContent = 'Erro ao carregar';
      this.wasmStatus.style.borderColor = '#f87171';
      this.wasmStatus.style.color = '#f87171';
      this.printLine(`Erro fatal ao carregar rsa.wasm: ${err.message}`, 'term-error');
    }
  }

  handleInputKeydown(e) {
    if (e.key === 'Enter') {
      const command = this.terminalInput.value.trim();
      this.terminalInput.value = '';

      if (command) {
        this.history.push(command);
        this.historyIndex = this.history.length;
        this.executeCommand(command);
      }
    } else if (e.key === 'ArrowUp') {
      if (this.historyIndex > 0) {
        this.historyIndex--;
        this.terminalInput.value = this.history[this.historyIndex];
      }
      e.preventDefault();
    } else if (e.key === 'ArrowDown') {
      if (this.historyIndex < this.history.length - 1) {
        this.historyIndex++;
        this.terminalInput.value = this.history[this.historyIndex];
      } else {
        this.historyIndex = this.history.length;
        this.terminalInput.value = '';
      }
      e.preventDefault();
    }
  }

  printLine(text, className = '') {
    const div = document.createElement('div');
    div.className = `terminal-line ${className}`;
    div.textContent = text;
    this.terminalOutput.appendChild(div);
    this.scrollToBottom();
  }

  printHtml(html) {
    const div = document.createElement('div');
    div.className = 'terminal-line';
    div.innerHTML = html;
    this.terminalOutput.appendChild(div);
    this.scrollToBottom();
  }

  scrollToBottom() {
    const container = document.getElementById('terminal-body');
    container.scrollTop = container.scrollHeight;
  }

  clearTerminal() {
    this.terminalOutput.innerHTML = '';
  }

  executeCommand(cmdLine) {
    this.printHtml(`<span class="term-prompt">user@rsa-zig:~$</span> ${cmdLine}`);
    const parts = cmdLine.split(' ').filter(p => p.length > 0);
    const cmd = parts[0].toLowerCase();

    if (cmd === 'clear') {
      this.clearTerminal();
      return;
    }

    if (cmd === 'help') {
      this.printLine(`Comandos disponíveis:`);
      this.printLine(`  rsa keygen            - Gera novo par de chaves RSA-2048`);
      this.printLine(`  rsa encrypt <msg>     - Criptografa mensagem usando OAEP-SHA256`);
      this.printLine(`  rsa decrypt [cifra]   - Decifra o texto Base64 via CRT (Garner)`);
      this.printLine(`  rsa inspect           - Exibe os parâmetros matemáticos atuais`);
      this.printLine(`  clear                 - Limpa o terminal`);
      return;
    }

    if (cmd === 'rsa') {
      const sub = parts[1] ? parts[1].toLowerCase() : '';
      if (sub === 'keygen') {
        this.executeKeygen();
      } else if (sub === 'encrypt') {
        const msg = parts.slice(2).join(' ');
        if (!msg) {
          this.printLine('Erro: uso correto é rsa encrypt <mensagem>', 'term-error');
        } else {
          this.executeEncrypt(msg);
        }
      } else if (sub === 'decrypt') {
        const cipher = parts[2] || this.cachedKeys.lastCipher;
        if (!cipher) {
          this.printLine('Erro: informe o texto cifrado em Base64 ou execute encrypt antes.', 'term-error');
        } else {
          this.executeDecrypt(cipher);
        }
      } else if (sub === 'inspect') {
        this.executeInspect();
      } else {
        this.printLine(`Subcomando 'rsa ${sub}' não reconhecido. Digite 'help'.`, 'term-error');
      }
      return;
    }

    this.printLine(`Comando '${cmd}' não reconhecido. Digite 'help' para ajuda.`, 'term-error');
  }

  injectBrowserEntropy() {
    const seedPtr = this.wasm.wasm_get_seed_ptr();
    const entropy = new Uint8Array(64);
    window.crypto.getRandomValues(entropy);
    const wasmMem = new Uint8Array(this.memory.buffer);
    wasmMem.set(entropy, seedPtr);
  }

  executeKeygen() {
    if (!this.wasm) return;

    this.printLine('[*] Injetando 64 bytes de entropia via window.crypto.getRandomValues()...', 'term-cyan');
    this.injectBrowserEntropy();

    this.printLine('[*] Executando Crivo de Eratóstenes + Miller-Rabin de 32 rodadas no WASM...', 'term-cyan');
    const start = performance.now();

    // 32 rodadas no navegador para resposta ágil mantendo segurança altíssima (2^-64)
    const err = this.wasm.wasm_keygen(32);
    const elapsed = Math.round(performance.now() - start);

    if (err !== 0) {
      this.printLine(`Erro na geração de chaves (código ${err}).`, 'term-error');
      return;
    }

    // Lê as chaves PEM geradas diretamente da memória linear
    const pubPtr = this.wasm.wasm_get_pub_ptr();
    const pubLen = this.wasm.wasm_get_pub_len();
    const privPtr = this.wasm.wasm_get_priv_ptr();
    const privLen = this.wasm.wasm_get_priv_len();

    const wasmMem = new Uint8Array(this.memory.buffer);
    const pubPem = this.decoder.decode(wasmMem.slice(pubPtr, pubPtr + pubLen));
    const privPem = this.decoder.decode(wasmMem.slice(privPtr, privPtr + privLen));

    this.cachedKeys.pubPem = pubPem;
    this.cachedKeys.privPem = privPem;

    // Lê parâmetros matemáticos do JSON de inspeção
    const inspectPtr = this.wasm.wasm_get_inspect_ptr();
    const inspectLen = this.wasm.wasm_get_inspect_len();
    const inspectJsonStr = this.decoder.decode(wasmMem.slice(inspectPtr, inspectPtr + inspectLen));
    const inspect = JSON.parse(inspectJsonStr);
    this.cachedKeys.inspectData = inspect;

    // Atualiza UI
    this.metricKeygenTime.textContent = `${elapsed} ms`;
    this.dispP.textContent = inspect.p;
    this.dispQ.textContent = inspect.q;
    this.dispN.textContent = inspect.n;
    this.dispD.textContent = inspect.d;
    this.dispDp.textContent = inspect.dp;
    this.dispDq.textContent = inspect.dq;
    this.dispQinv.textContent = inspect.q_inv;

    this.printLine(`[+] Par de chaves RSA-2048 gerado com sucesso em ${elapsed} ms!`, 'term-green');
    this.printLine(`    Módulo n: ${inspect.n.substring(0, 32)}... (${inspect.n.length - 2} caracteres hex)`);
    this.printLine(`    λ(n) invertido com sucesso via Euclides Estendido sobre i4096.`);
    this.printLine(`    Parâmetros CRT (dp, dq, q_inv) pré-calculados para o Algoritmo de Garner.`);
  }

  executeEncrypt(msg) {
    if (!this.wasm) return;
    if (!this.cachedKeys.pubPem) {
      this.printLine('[!] Nenhuma chave pública carregada. Gerando chaves primeiro...', 'term-amber');
      this.executeKeygen();
    }

    this.injectBrowserEntropy();

    const msgBytes = this.encoder.encode(msg);
    if (msgBytes.length > 190) {
      this.printLine('Erro: mensagem excede 190 bytes (limite do OAEP-SHA256 para RSA-2048).', 'term-error');
      return;
    }

    const pubPtr = this.wasm.wasm_get_pub_ptr();
    const pubLen = this.wasm.wasm_get_pub_len();
    const msgPtr = this.wasm.wasm_get_msg_ptr();

    const wasmMem = new Uint8Array(this.memory.buffer);
    wasmMem.set(msgBytes, msgPtr);

    const start = performance.now();
    const err = this.wasm.wasm_encrypt(pubLen, msgBytes.length);
    const elapsed = (performance.now() - start).toFixed(2);

    if (err !== 0) {
      this.printLine(`Erro ao criptografar mensagem (código ${err}).`, 'term-error');
      return;
    }

    const cipherPtr = this.wasm.wasm_get_cipher_ptr();
    const cipherLen = this.wasm.wasm_get_cipher_len();
    const cipherB64 = this.decoder.decode(wasmMem.slice(cipherPtr, cipherPtr + cipherLen));

    this.cachedKeys.lastCipher = cipherB64;
    this.dispCipher.textContent = cipherB64;

    this.printLine(`[+] Mensagem criptografada com sucesso em ${elapsed} ms!`, 'term-green');
    this.printLine(`    Texto original: "${msg}" (${msgBytes.length} bytes)`);
    this.printLine(`    Padding: OAEP (SHA-256 + MGF1 com seed aleatório)`);
    this.printLine(`    Cifra Base64 (344 caracteres):`);
    this.printLine(`    ${cipherB64}`, 'term-cyan');
  }

  executeDecrypt(cipherB64Input = null) {
    if (!this.wasm) return;
    if (!this.cachedKeys.privPem) {
      this.printLine('[!] Nenhuma chave privada carregada. Gere as chaves primeiro.', 'term-error');
      return;
    }

    const cipherB64 = cipherB64Input || this.cachedKeys.lastCipher;
    if (!cipherB64) {
      this.printLine('[!] Nenhum texto cifrado disponível para descriptografia.', 'term-error');
      return;
    }

    const cipherBytes = this.encoder.encode(cipherB64.trim());
    if (cipherBytes.length !== 344) {
      this.printLine(`[!] Tamanho de cifra inválido: esperado 344 caracteres Base64, recebido ${cipherBytes.length}.`, 'term-error');
      return;
    }

    const privLen = this.wasm.wasm_get_priv_len();
    const cipherPtr = this.wasm.wasm_get_cipher_ptr();

    const wasmMem = new Uint8Array(this.memory.buffer);
    wasmMem.set(cipherBytes, cipherPtr);

    const start = performance.now();
    const err = this.wasm.wasm_decrypt(privLen, cipherBytes.length);
    const elapsed = (performance.now() - start).toFixed(2);

    if (err !== 0) {
      this.printLine(`[!] Falha na descriptografia ou padding OAEP inválido (código ${err}).`, 'term-error');
      return;
    }

    const msgPtr = this.wasm.wasm_get_msg_ptr();
    const msgLen = this.wasm.wasm_get_msg_len();
    const plainText = this.decoder.decode(wasmMem.slice(msgPtr, msgPtr + msgLen));

    this.printLine(`[+] Descriptografia via Teorema Chinês dos Restos (CRT) concluída em ${elapsed} ms!`, 'term-green');
    this.printLine(`    Recombinação de Garner: m = m₂ + (q_inv · (m₁ - m₂) mod p) · q`);
    this.printLine(`    Texto decifrado recuperado:`, 'term-amber');
    this.printLine(`    "${plainText}"\n`, 'term-green');
  }

  executeInspect() {
    if (!this.cachedKeys.inspectData) {
      this.printLine('[!] Nenhuma chave gerada ainda. Execute rsa keygen primeiro.', 'term-amber');
      return;
    }

    const d = this.cachedKeys.inspectData;
    this.printLine('=== PARÂMETROS MATEMÁTICOS ATUAIS (RSA-2048) ===', 'term-cyan');
    this.printLine(`  e     : ${d.e}`);
    this.printLine(`  p     : ${d.p}`);
    this.printLine(`  q     : ${d.q}`);
    this.printLine(`  n     : ${d.n}`);
    this.printLine(`  d     : ${d.d}`);
    this.printLine(`  dp    : ${d.dp}`);
    this.printLine(`  dq    : ${d.dq}`);
    this.printLine(`  q_inv : ${d.q_inv}`);
    this.printLine('================================================', 'term-cyan');
  }
}

// Inicializa a aplicação ao carregar o DOM
window.addEventListener('DOMContentLoaded', () => {
  window.terminalApp = new RsaWebTerminal();
});
