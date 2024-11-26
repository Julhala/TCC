from easy.models import Cadastro  # Importe seu modelo

# Tente criar um novo registro
try:
    cadastro = Cadastro(nome='Teste', sobrenome='User', cpf='12345678901', telefone='11999999999', senha='senha123')
    cadastro.save()  # Tente salvar
    print("Cadastro salvo com sucesso!")
except Exception as e:
    print(f"Erro ao salvar: {e}")

# Tente buscar registros existentes
try:
    registros = Cadastro.objects.all()
    print(f"Registros encontrados: {registros.count()}")
except Exception as e:
    print(f"Erro ao buscar registros: {e}")
