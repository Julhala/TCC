from .models import Maquina, Funcionario, agendamento
from django.db import IntegrityError
from django.contrib.auth.hashers import make_password
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.db import connection
from django.contrib import messages
from django.shortcuts import render, redirect
from .models import agendamento
from django.contrib.auth.hashers import check_password
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from .models import Maquina

from django.contrib.auth.decorators import login_required

@login_required
def sua_view(request):
    # Pegue os dados do usuário autenticado
    usuario = Funcionario.objects.get(id=request.user.id)  # Ajuste se você estiver usando outro modelo de usuário
    return render(request, 'caminho/para/seu/template.html', {'usuario': usuario})




@csrf_exempt
def atualizar_status_maquina(request, id):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            novo_status = data.get('status')
            maquina = Maquina.objects.get(id=id)
            maquina.status = novo_status  # Adicione um campo 'status' no modelo se ainda não tiver
            maquina.save()
            return JsonResponse({'message': 'Status atualizado com sucesso!'}, status=200)
        except Maquina.DoesNotExist:
            return JsonResponse({'error': 'Máquina não encontrada.'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

def obter_eventos(request):
    month = request.GET.get('month')
    year = request.GET.get('year')
    eventos_list = []

    if month and year:
        eventos = agendamento.objects.filter(dia__month=month, dia__year=year)
        eventos_list = [{'dia': evento.dia.strftime('%Y-%m-%d'), 'nome': evento.nome, 'tipomanu': evento.tipomanu} for evento in eventos]

    return JsonResponse(eventos_list, safe=False)


# Login ADMIN
USUARIO_FIXO = 'Admin'
SENHA_FIXA = '@801'

def login_admin(request):
    global usuarioLogado
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        if username == USUARIO_FIXO and password == SENHA_FIXA:
            usuarioLogado = username
            return redirect('menuadmin')  # Redireciona após o login
        else:
            messages.error(request, 'Usuário ou senha inválidos.')

    return render(request, 'easy/loginadmin.html')


# Login Docente
def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('nome')  # O nome do usuário
        password = request.POST.get('senha')  # A senha fornecida

        print(f"Username: {username}")

        if not username or not password:
            messages.error(request, "Por favor, preencha todos os campos.")
            return render(request, 'easy/logindocente.html')

        # Buscar no banco de dados usando o nome de usuário fornecido
        with connection.cursor() as cursor:
            cursor.execute("SELECT senha FROM funcionario WHERE LOWER(nome) = LOWER(%s)", [username])
            result = cursor.fetchone()

        if result:
            # Se o usuário for encontrado, obter a senha criptografada
            senha_ofc = result[0]  # result[0] é a senha armazenada no banco de dados

            # Verificar se a senha fornecida corresponde à senha criptografada
            if check_password(password, senha_ofc):  # Usando check_password para verificar a senha
                messages.success(request, "Login bem-sucedido!")
                return redirect('menu')  # Redirecionar para a página inicial após o login bem-sucedido
            else:
                messages.error(request, "Senha incorreta!")  # Senha não confere
        else:
            messages.error(request, 'Usuário inexistente ou senha inválida.')  # Usuário não encontrado

    return render(request, 'easy/logindocente.html')  # Renderiza o template de login



# Função responsável pelo formulário de docente
usuarioLogado = None  # Defina um valor padrão

def cadastrar_usuario(request):
    global usuarioLogado
    if request.method == 'POST':
        nome = request.POST.get('nome')
        sobrenome = request.POST.get('sobrenome')
        cpf = request.POST.get('cpf')
        telefone = request.POST.get('telefone')
        senha = request.POST.get('senha')

        # Criptografa a senha antes de salvar no banco
        senha_criptografada = make_password(senha)

        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO funcionario (nome, sobrenome, senha, cpf, telefone) VALUES (%s, %s, %s, %s, %s)",
                    [nome, sobrenome, senha_criptografada, cpf, telefone]  # Usa a senha criptografada
                )
            messages.success(request, 'Cadastro realizado com sucesso!')
            return redirect('menu')  # Redirecionar para a página desejada após o cadastro

        except Exception as e:
            messages.error(request, f'Erro ao realizar o cadastro: {e}')
        except IntegrityError:
            messages.error(request, 'Erro: CPF já cadastrado.')  # Erro se CPF for duplicado

    return render(request, 'easy/cadastrar_funcionarios.html', {'usuarioLogado': usuarioLogado})

# Função responsável pelo formílário de Máquinas
def cadastrar_maquina(request):
    global usuarioLogado

    # Inicializa 'usuarioLogado' se não estiver definido
    if 'usuarioLogado' not in globals() or not usuarioLogado:
        usuarioLogado = 'Desconhecido'  # ou outro valor padrão

    if request.method == 'POST':
        nome = request.POST.get('nome')
        tipomaq = request.POST.get('tipomaq')
        tipomanu = request.POST.get('tipomanu')
        descricao = request.POST.get('descricao')
        imagem = request.FILES.get('imagem')

        try:
            # Salva a imagem usando o sistema de arquivos do Django
            if imagem:
                imagem_nome = default_storage.save(imagem.name, ContentFile(imagem.read()))

            with connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO maquinas (nome, tipomaq, tipomanu, descricao, imagem) VALUES (%s, %s, %s, %s, %s)",
                    [nome, tipomaq, tipomanu, descricao, imagem_nome]
                )
            messages.success(request, 'Cadastro realizado com sucesso!')
            return redirect('cadastrarmaq')
        except Exception as e:
            messages.error(request, f'Erro ao realizar o cadastro: {e}')

    # Passa 'usuarioLogado' para o template, garantindo que tenha valor
    return render(request, 'easy/cadastro_maquina.html', {'usuarioLogado': usuarioLogado})


def agenda(request):
    if request.method == 'POST':
        nome = request.POST.get('nome')
        tipomanu = request.POST.get('tipomanu')
        dia = request.POST.get('dia')
        hora = request.POST.get('hora')
        quem = request.POST.get('quem')

        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO agendamento (nome, tipomanu, dia, hora, quem) VALUES (%s, %s, %s, %s, %s)",
                    [nome, tipomanu, dia, hora, quem]
                )
            messages.success(request, 'Agendamento salvo com sucesso!')
        except Exception as e:
            messages.error(request, f'Erro ao salvar agendamento: {e}')

        return redirect('calendario')  # Redireciona para a página do calendário

    return render(request, 'easy/agenda.html')  # Renderiza o formulário de agendamento

def manual_maquinas(request):
    maquinas = Maquina.objects.all()  # Buscar todas as máquinas no banco de dados
    return render(request, 'easy/galeria_doc.html', {'maquinas': maquinas})

def capa(request):
    return render(request, 'easy/capa.html')

def menu(request):
    return render(request, 'easy/menu.html')

def menuadmin(request):
    return render(request, 'easy/menuadm.html')

def calendario(request):
    return render(request, 'easy/calendario.html')