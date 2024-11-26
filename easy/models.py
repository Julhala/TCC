from django.db import models
class Cadastro(models.Model):


    nome = models.CharField(max_length=100)
    sobrenome = models.CharField(max_length=100)
    senha = models.CharField(max_length=100)
    cpf = models.CharField(max_length=11)
    telefone = models.CharField(max_length=15)

    def __str__(self):
        return f'{self.nome} {self.sobrenome}'
        # Ao imprimir ou exibir uma instância de 'Cadastro', ele retornará o nome completo do usuário (nome + sobrenome).

class Maquina(models.Model):
    nome = models.CharField(max_length=255)
    tipomaq = models.CharField(max_length=255)
    tipomanu = models.CharField(max_length=255)
    descricao = models.TextField()
    imagem = models.ImageField(upload_to='images/')
    status = models.CharField(max_length=10, default='ativo')
    def __str__(self):
        return self.nome
class Funcionario(models.Model):
    nome = models.CharField(max_length=100)
    sobrenome = models.CharField(max_length=100)
    cpf = models.CharField(max_length=11, unique=True)  # CPF deve ser único
    telefone = models.CharField(max_length=15)
    senha = models.CharField(max_length=128)  # Considere usar um hash de senha

    def __str__(self):
        return f"{self.nome} {self.sobrenome}"

class agendamento(models.Model):
    nome = models.CharField(max_length=255)
    tipomanu = models.CharField(max_length=100)
    dia = models.DateField()
    hora = models.TimeField()
    quem = models.CharField(max_length=255)

    class Meta:
        db_table = 'agendamento'  # Define o nome da tabela

    def __str__(self):
        return f"{self.nome} em {self.dia}"

