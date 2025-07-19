# Implementar uma Rainbow Table
# O alfabeto deve ter 70 caracteres
# A tabela precisa ser colorida (a comentada em aula é monocromatica!!)
# O tamanho da senha deve ter a partir de 5 caracteres
# Apresentar testes e conclusões!! (fazer a tabela é facil!!)
# A função SHA512 deve ser o alvo da tabela
# Grupos de até 2 alunos
# A tabela será testada após a entrega....

import hashlib
import string
import random
import pickle
import time
import os
import sys
from typing import Dict, Set
from multiprocessing import Pool, cpu_count
import struct

# --- CONFIGURAÇÕES GLOBAIS ---
ALPHABET = string.ascii_letters + string.digits + "!@#$|%&*"
PASSWORD_LENGTH = 6  # Tamanho da senha
CHAIN_LENGTH = 5000  # Comprimento de cada corrente
TABLE_SIZE = 12000000  # Número de correntes na tabela
TABLE_FILENAME = "rainbow_table6.pkl" #nome do arquivo
CHUNK_SIZE = 1000  # Tamanho do chunk para processamento paralelo

ALPHABET_SIZE = len(ALPHABET)  # 70 caracteres
KEYSPACE_SIZE = ALPHABET_SIZE ** PASSWORD_LENGTH  # 70^5 = 16,807,000,000 combinações
HASH_STRUCT = struct.Struct('Q')  # Para conversão mais rápida de hash


def hash_sha512(password: str) -> str:
    """
    Recebe uma senha em lingua normal e retorn o sha512
    """
    return hashlib.sha512(password.encode('utf-8')).hexdigest()


def reduction_function_optimized(hash_hex: str, round_index: int) -> str:
    """
    Função de redução "colorida" que converte hash em senha.

    round_index garante uma função de redução diferente para cada posição da corrente.

        hash_hex: Hash em formato hexadecimal
        round_index: Índice da rodada (0 a CHAIN_LENGTH-1)
        Retorna a senha resultante da redução
    """
    # Otimização: usa apenas os primeiros 16 chars do hash (64 bits)
    # Isso é suficiente para gerar senhas de 5 caracteres
    hash_int = int(hash_hex[:16], 16)

    # Adiciona o round_index para implementar a "cor"
    # Cada posição da corrente terá uma função de redução diferente
    num = (hash_int + round_index) % KEYSPACE_SIZE

    # Conversão otimizada para base do alfabeto
    # Constrói a senha dígito por dígito
    password = []
    for _ in range(PASSWORD_LENGTH):
        password.append(ALPHABET[num % ALPHABET_SIZE])
        num //= ALPHABET_SIZE

    # Inverte para manter a ordem correta
    return ''.join(reversed(password))


def generate_chain(start_password: str) -> tuple:
    """
    Gera uma corrente completa da Rainbow Table.
    senha -> hash -> redução -> senha -> hash -> redução -> ...

    Recebe senha incial
    Retorna Tupla (ponto_final, ponto_inicial) da corrente
    """
    current_password = start_password

    # Executa CHAIN_LENGTH passos de hash-redução
    for round_index in range(CHAIN_LENGTH):
        # Calcula o hash da senha atual
        hash_hex = hash_sha512(current_password)

        # Aplica a função de redução, leia a função pra entender como funciona
        current_password = reduction_function_optimized(hash_hex, round_index)

    # Retorna o ponto final e inicial da corrente
    return current_password, start_password


def generate_chunk(chunk_data: tuple) -> Dict[str, str]:
    """
    Gera um chunk da tabela para processamento paralelo.

    recebe chunk_data: Tupla (lista_senhas, id_chunk)

    Retorna um dicionário com as correntes do chunk {ponto_final: ponto_inicial}
    """
    start_passwords, chunk_id = chunk_data
    chunk_table = {}

    # Gera uma corrente para cada senha inicial
    for password in start_passwords:
        final_password, initial_password = generate_chain(password)
        chunk_table[final_password] = initial_password

    return chunk_table


def generate_unique_passwords(count: int) -> Set[str]:
    """
    Gera senhas iniciais únicas de forma eficiente.

    É importante que as senhas sejam únicas para evitar correntes
    duplicadas na tabela

    count: Número de senhas únicas a gerar

    Retorna as senhas únicas geradas
    """
    print(f"Gerando {count} senhas iniciais únicas...")
    passwords = set()

    # Gera em lotes para melhor performance
    batch_size = min(10000, count)

    while len(passwords) < count:
        # Gera um lote de senhas usando random.choices (mais rápido)
        batch = {''.join(random.choices(ALPHABET, k=PASSWORD_LENGTH))
                 for _ in range(batch_size)}

        # Adiciona ao conjunto (duplicatas são automaticamente removidas)
        passwords.update(batch)

        # Exibe progresso a cada 50k senhas
        if len(passwords) % 50000 == 0:
            print(f"  ... {len(passwords)}/{count} senhas geradas.")

    # Retorna exatamente o número solicitado
    return set(list(passwords)[:count])


def generate_rainbow_table_parallel():
    """
    Gera a Rainbow Table usando processamento paralelo.

    A paralelização é feita dividindo a geração em chunks que são
    processados independentemente em diferentes núcleos do CPU.

    Returns:
        Dicionário com a tabela completa {ponto_final: ponto_inicial}
    """
    print("=" * 60)
    print(f"Gerando Rainbow Table OTIMIZADA:")
    print(f"  • Tamanho da tabela: {TABLE_SIZE:,} correntes")
    print(f"  • Tamanho da corrente: {CHAIN_LENGTH:,} passos")
    print(f"  • Tamanho do alfabeto: {ALPHABET_SIZE} caracteres")
    print(f"  • Tamanho da senha: {PASSWORD_LENGTH} caracteres")
    print(f"  • Espaço de chaves: {KEYSPACE_SIZE:,}")
    print(f"  • Processadores: {cpu_count()}")
    print("=" * 60)

    start_time = time.time()

    # Gera senhas iniciais únicas para evitar correntes duplicadas
    initial_passwords = generate_unique_passwords(TABLE_SIZE)

    # Divide as senhas em chunks para processamento paralelo
    password_list = list(initial_passwords)
    chunks = []

    for i in range(0, len(password_list), CHUNK_SIZE):
        chunk = password_list[i:i + CHUNK_SIZE]
        chunks.append((chunk, i // CHUNK_SIZE))

    print(f"\nProcessando {len(chunks)} chunks em paralelo...")

    # Processa chunks em paralelo usando todos os núcleos disponíveis
    rainbow_table = {}

    with Pool(processes=cpu_count()) as pool:
        # pool.imap processa os chunks conforme ficam prontos
        for i, chunk_result in enumerate(pool.imap(generate_chunk, chunks)):
            # Combina os resultados de cada chunk na tabela final
            rainbow_table.update(chunk_result)

            # Calcula e exibe o progresso
            progress = ((i + 1) / len(chunks)) * 100
            chains_processed = (i + 1) * CHUNK_SIZE
            if chains_processed > TABLE_SIZE:
                chains_processed = TABLE_SIZE

            print(f"  ... {chains_processed:,}/{TABLE_SIZE:,} correntes processadas ({progress:.1f}%)")

    end_time = time.time()
    generation_time = end_time - start_time

    print(f"\n[SUCESSO] Tabela gerada em {generation_time:.2f} segundos")
    print(f"Performance: {TABLE_SIZE / generation_time:.0f} correntes/segundo")

    return rainbow_table


def save_table(rainbow_table: Dict[str, str]):
    """
    Salva a tabela no disco

    Além da tabela, salva metadados importantes para validação
    e análise posterior.
    """
    print(f"\nSalvando tabela no arquivo '{TABLE_FILENAME}'...")

    save_start = time.time()
    try:
        # Prepara dados para salvar: tabela + metadados
        table_data = {
            'table': rainbow_table,
            'metadata': {
                'alphabet': ALPHABET,
                'password_length': PASSWORD_LENGTH,
                'chain_length': CHAIN_LENGTH,
                'table_size': TABLE_SIZE,
                'generation_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'keyspace_size': KEYSPACE_SIZE,
                'coverage': (TABLE_SIZE * CHAIN_LENGTH) / KEYSPACE_SIZE * 100
            }
        }

        # Salva usando o protocolo pickle mais eficiente
        with open(TABLE_FILENAME, 'wb') as f:
            pickle.dump(table_data, f, protocol=pickle.HIGHEST_PROTOCOL)

        save_time = time.time() - save_start
        file_size = os.path.getsize(TABLE_FILENAME) / (1024 * 1024)  # em MB

        print(f"[SUCESSO] Tabela salva em {save_time:.2f} segundos")
        print(f"Tamanho do arquivo: {file_size:.2f} MB")

    except IOError as e:
        print(f"[ERRO] Não foi possível salvar a tabela: {e}")
        sys.exit(1)


def print_statistics(rainbow_table: Dict[str, str]):
    """
    Exibe estatísticas detalhadas da tabela gerada.
    """
    print("\n" + "=" * 60)
    print("ESTATÍSTICAS DA TABELA GERADA:")
    print("=" * 60)

    # Estatísticas básicas
    print(f"Entradas na tabela: {len(rainbow_table):,}")
    print(f"Cobertura teórica: {(TABLE_SIZE * CHAIN_LENGTH) / KEYSPACE_SIZE * 100:.4f}%")
    print(f"Eficiência: {len(rainbow_table) / TABLE_SIZE * 100:.2f}%")

    # Análise de colisões
    colisoes = TABLE_SIZE - len(rainbow_table)
    print(f"Colisões estimadas: {colisoes:,}")

    # Probabilidade de sucesso
    print(f"Espaço de chaves: {KEYSPACE_SIZE:,}")
    print(f"Probabilidade de sucesso: ~{len(rainbow_table) / KEYSPACE_SIZE * 100:.6f}%")

    print("=" * 60)


def main():
    """
    Controla o fluxo completo: verificação de arquivos existentes,
    geração da tabela, exibição de estatísticas e salvamento.
    """
    print("Rainbow Table Generator - Versão Otimizada")
    print(f"Alfabeto: {ALPHABET}")
    print(f"Tamanho do alfabeto: {ALPHABET_SIZE} caracteres")

    # Verifica se já existe uma tabela
    if os.path.exists(TABLE_FILENAME):
        choice = input(f"\nAVISO: O arquivo '{TABLE_FILENAME}' já existe. "
                       f"Deseja sobrescrevê-lo? (s/n): ").lower().strip()
        if choice != 's':
            print("Operação cancelada.")
            return

    try:
        # Gera a tabela usando processamento paralelo
        rainbow_table = generate_rainbow_table_parallel()

        # Exibe estatísticas detalhadas
        print_statistics(rainbow_table)

        # Salva a tabela no disco
        save_table(rainbow_table)

        print(f"\n[CONCLUÍDO] Rainbow Table gerada com sucesso!")
        print(f"Use o script de crack para testar a tabela.")

    except KeyboardInterrupt:
        print("\n[INTERROMPIDO] Geração cancelada pelo usuário.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERRO] Falha na geração: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()