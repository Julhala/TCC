from .models import Cadastro, Maquina, agendamento
from django.contrib.auth import authenticate
from django import forms


# Login de Docente
class LoginForm(forms.Form):
    username = forms.CharField(max_length=150)
    password = forms.CharField(widget=forms.PasswordInput)

    def clean(self):
        cleaned_data = super().clean()
        username = cleaned_data.get('username')
        password = cleaned_data.get('password')

        if username and password:
            user = authenticate(username=username, password=password)

            if user is None:
                raise forms.ValidationError("Usuário ou senha inválidos.")
            elif not user.is_active:
                raise forms.ValidationError("Usuário está desativado.")

        return cleaned_data


# Cadastro de Docente
class CadastroForm(forms.ModelForm):
    senha = forms.CharField(widget=forms.PasswordInput)
    # Sobrescreve o campo 'senha' para ser do tipo 'CharField' com um widget que oculta o texto (campo de senha).

    class Meta:
        # Classe interna que contém configurações adicionais sobre o formulário.
        model = Cadastro
        # Indica que o formulário será baseado no modelo 'Cadastro', criando automaticamente campos correspondentes aos do modelo.
        fields = ['nome', 'sobrenome', 'senha_hash', 'cpf', 'telefone']
        # Define explicitamente os campos do formulário que serão exibidos. Somente esses campos estarão presentes no formulário gerado.


# Cadastro de Máquina
class Cadastromaq(forms.ModelForm):
    class Meta:
        model = Maquina
        fields = ['nome', 'tipomaq', 'tipomanu', 'descricao', 'imagem']

class agendamento(forms.ModelForm):
    class Meta:
        model = agendamento
        fields = ['id', 'nome', 'tipomanu', 'dia', 'hora', 'quem', 'created_at']
