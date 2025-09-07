# 🔓 Decryptor ENC3 – OTC v8 (Windows)

Este projeto é um **decryptor de arquivos ENC3** usado pelo **OTClient v8 (dev)**.
Foi desenvolvido em **C++17** e funciona no **Windows**, suportando **multithreading** para processar vários arquivos em paralelo com mais velocidade.

---

## ⚙️ Como funciona

* Procura automaticamente arquivos **ENC3** dentro das pastas:

  * `data/`
  * `modules/`
  * `mods/`
  * `layouts/`
  * `init.lua`
* Lê o cabeçalho (`ENC3`), chave e informações de tamanho.
* Descriptografa usando uma variação do **XXTEA**.
* Descompacta os dados com **zlib**.
* Valida integridade com **Adler32**.
* Salva o arquivo descriptografado no lugar do original (com **backup automático**).
* Mostra o progresso em tempo real (sucessos, falhas e ignorados).

---

## 📂 Arquivos suportados

Esse decryptor consegue descriptografar os principais formatos do OTC v8:

* **.png** → imagens
* **.otui** → interface do client
* **.otmod** → módulos
* **.lua** → scripts (⚠️ ficam em **bytecode** do OTC v8; para usar como `.lua` normal é necessário converter bytecode → source)

---

## 🔑 Sobre os deltas

O código já está configurado com os **deltas do OTC v8 dev**.
Caso queira adaptar para outro client, será necessário fazer **engenharia reversa** para descobrir os deltas corretos.

---

## 📚 Dependências (Windows)

* **Compilador com suporte a C++17**

  * [MSVC](https://visualstudio.microsoft.com/) (Visual Studio)
  * ou [MinGW-w64](https://www.mingw-w64.org/)
* **zlib**

  * Recomendado instalar via [vcpkg](https://github.com/microsoft/vcpkg):

```powershell
vcpkg install zlib
```

---

## 🚀 Como compilar (Windows)

### Usando MinGW

```powershell
g++ -std=c++17 main.cpp -lz -o decryptor.exe
```

### Usando MSVC (Developer Command Prompt)

```powershell
cl /std:c++17 main.cpp zlib.lib
```

---

## 📊 Exemplos de execução

Rodando sem argumentos (procura nas pastas padrão do OTC):

```powershell
decryptor.exe
```

Rodando em arquivos/pastas específicas:

```powershell
decryptor.exe data\modules\
decryptor.exe init.lua
```

## ⚠️ Aviso

* Os arquivos `.lua` descriptografados permanecem em **bytecode v8** → é necessário converter para texto se quiser editar.
* Este projeto foi feito para **uso pessoal e educacional**.
* Caso use em outros clients, será necessário ajustar os **deltas** via engenharia reversa.

