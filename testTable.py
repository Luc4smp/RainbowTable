#!/usr/bin/env python3
"""Rainbow Table Crack - Versão Compacta"""

import hashlib
import string
import random
import pickle
import time
import os
import sys
from typing import Dict, Optional

# Configurações
ALPHABET = string.ascii_letters + string.digits + "!@#$|%&*"
PASSWORD_LENGTH = 5
CHAIN_LENGTH = 10000
TABLE_FILENAME = "rainbow_table5.pkl"
KEYSPACE_SIZE = len(ALPHABET) ** PASSWORD_LENGTH


def hash_sha512(password: str) -> str:
    return hashlib.sha512(password.encode('utf-8')).hexdigest()


def reduction_function_optimized(hash_hex: str, round_index: int) -> str:
    hash_int = int(hash_hex[:16], 16)
    num = (hash_int + round_index) % KEYSPACE_SIZE
    password = []
    for _ in range(PASSWORD_LENGTH):
        password.append(ALPHABET[num % len(ALPHABET)])
        num //= len(ALPHABET)
    return ''.join(reversed(password))


def load_rainbow_table() -> Dict[str, str]:
    if not os.path.exists(TABLE_FILENAME):
        print(f"[ERRO] Arquivo '{TABLE_FILENAME}' não encontrado.")
        sys.exit(1)

    print(f"Carregando Rainbow Table...")
    with open(TABLE_FILENAME, 'rb') as f:
        table_data = pickle.load(f)

    # Suporte para formato novo e antigo
    if isinstance(table_data, dict) and 'table' in table_data:
        return table_data['table']
    return table_data


def crack_hash(target_hash: str, rainbow_table: Dict[str, str]) -> Optional[str]:
    print(f"Tentando quebrar hash: {target_hash}...")

    for start_pos in range(CHAIN_LENGTH - 1, -1, -1):
        current_hash = target_hash

        for pos in range(start_pos, CHAIN_LENGTH):
            password = reduction_function_optimized(current_hash, pos)

            if password in rainbow_table:
                # Reconstrói a corrente do início
                current_password = rainbow_table[password]
                for i in range(CHAIN_LENGTH):
                    if hash_sha512(current_password) == target_hash:
                        return current_password
                    current_password = reduction_function_optimized(hash_sha512(current_password), i)
                break

            current_hash = hash_sha512(password)
    return None


def crack_specific_hash(rainbow_table: Dict[str, str]):
    #Função que tenta achar a senha dado um hash
    print(f"\n=== QUEBRAR HASH ESPECÍFICO ===")
    print("Digite o hash SHA-512 para tentar quebrar")
    print("Digite 'back' para voltar ao menu principal")

    while True:
        try:
            user_input = input("\nDigite o hash: ").strip()

            if user_input.lower() == 'back':
                break

            # Validação básica do hash
            if len(user_input) != 128:
                print(f"[ERRO] Hash SHA-512 deve ter 128 caracteres hexadecimais.")
                print(f"Tamanho atual: {len(user_input)} caracteres")
                continue

            # Verificar se é hexadecimal válido
            try:
                int(user_input, 16)
            except ValueError:
                print("[ERRO] Hash deve conter apenas caracteres hexadecimais (0-9, a-f).")
                continue

            start_time = time.time()
            result = crack_hash(user_input, rainbow_table)
            elapsed_time = time.time() - start_time

            if result:
                print(f"✓ Senha encontrada: '{result}'")
                print(f"⏱ Tempo de busca: {elapsed_time:.2f}s")

                # Verificar se o hash está correto
                if hash_sha512(result) == user_input:
                    print("✓ Verificação: Hash confere!")
                else:
                    print("⚠ Atenção: Possível colisão de hash!")
            else:
                print("✗ Senha não encontrada na Rainbow Table.")
                print(f"⏱ Tempo de busca: {elapsed_time:.2f}s")

        except KeyboardInterrupt:
            print("\nVoltando ao menu principal...")
            break


def run_test(rainbow_table: Dict[str, str], num_tests: int = 10):
    #Testa se num_tests senhas estão na Rainbow Table
    print(f"\n=== TESTE DE PERFORMANCE - {num_tests} senhas ===")

    test_passwords = [''.join(random.choices(ALPHABET, k=PASSWORD_LENGTH)) for _ in range(num_tests)]
    successful_cracks = 0
    start_time = time.time()

    for i, password in enumerate(test_passwords):
        print(f"Teste {i + 1}/{num_tests} - Senha: '{password}'")
        target_hash = hash_sha512(password)
        result = crack_hash(target_hash, rainbow_table)

        if result:
            successful_cracks += 1
            print(f"  ✓ Sucesso: '{result}'")
        else:
            print(f"  ✗ Falha")

    total_time = time.time() - start_time
    success_rate = (successful_cracks / num_tests) * 100

    print(f"\n=== RESULTADOS ===")
    print(f"Sucessos: {successful_cracks}/{num_tests} ({success_rate:.1f}%)")
    print(f"Tempo total: {total_time:.2f}s")


def interactive_mode(rainbow_table: Dict[str, str]):
    #Verifica se uma senha específica está na Rainbow Table
    print(f"\n=== MODO INTERATIVO ===")
    print("Digite 'quit' para sair")

    while True:
        try:
            user_input = input("\nDigite uma senha para testar: ").strip()

            if user_input.lower() == 'quit':
                break

            if len(user_input) != PASSWORD_LENGTH:
                print(f"[ERRO] A senha deve ter {PASSWORD_LENGTH} caracteres.")
                continue

            if not all(c in ALPHABET for c in user_input):
                print(f"[ERRO] Caracteres não permitidos.")
                continue

            target_hash = hash_sha512(user_input)
            result = crack_hash(target_hash, rainbow_table)

            if result:
                print(f"✓ Senha encontrada: '{result}'")
                if result == user_input:
                    print("✓ Crack bem-sucedido!")
                else:
                    print("⚠ Colisão de hash!")
            else:
                print("✗ Senha não encontrada.")

        except KeyboardInterrupt:
            print("\nSaindo...")
            break


def main():
    print("Rainbow Table Crack - Versão Compacta")
    rainbow_table = load_rainbow_table()
    print(f"Tabela carregada: {len(rainbow_table):,} entradas")

    while True:
        print(f"\n=== MENU ===")
        print("1. Teste rápido (10 senhas)")
        print("2. Teste completo (100 senhas)")
        print("3. Modo interativo")
        print("4. Quebrar hash específico")
        print("5. Sair")

        try:
            choice = input("Escolha (1-5): ").strip()

            if choice == '1':
                run_test(rainbow_table, 10)
            elif choice == '2':
                run_test(rainbow_table, 100)
            elif choice == '3':
                interactive_mode(rainbow_table)
            elif choice == '4':
                crack_specific_hash(rainbow_table)
            elif choice == '5':
                print("Saindo...")
                break
            else:
                print("Opção inválida.")

        except KeyboardInterrupt:
            print("\nSaindo...")
            break


if __name__ == "__main__":
    main()