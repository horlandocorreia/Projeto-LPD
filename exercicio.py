import itertools

# Função para gerar permutações e imprimir
def gerar_permutacoes(numeros):
    permutacoes = list(itertools.permutations(numeros))
    for permutacao in permutacoes:
        print(permutacao)

# Solicitar entrada do usuário
entrada = input("Digite uma lista de números separados por espaços: ")
numeros = entrada.split()

# Converter os números para inteiros
numeros = [int(numero) for numero in numeros]

# Chamar a função para gerar e imprimir permutações
gerar_permutacoes(numeros)