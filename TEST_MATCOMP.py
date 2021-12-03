#!/usr/bin/env python
# coding: utf-8

# # <center>PROJETO FINAL - MATCOMP

# In[2]:


import string
import pandas as pd
import secrets
pd.set_option('display.max_rows', 100)

import string
import random


# In[13]:


rng = secrets.randbits(1000000)


# In[15]:


key = secrets.choice(range(128)) + rng
bin1 = bin(key)
bin1


# In[5]:


full_ascii = [char for char in ''.join(chr(i) for i in range(128))]
full_ascii


# In[6]:


data = {'String': [char for char in string.printable],
       'Unicode Values': [ord(char) for char in string.printable],
       'Binary Values': [bin(ord(char)) for char in string.printable]}

df = pd.DataFrame.from_dict(data)
df.set_index('String', inplace = True)
df[:36]


# In[7]:


int1, int2 = ord('e'), ord('0')
xor_num = int1 ^ int2
ascii_char = xor_num.to_bytes((xor_num.bit_length() + 7) // 8, byteorder = 'big').decode()
ascii_char


# In[8]:


binary1 = '01000001'
binary2 = '00110001'
bit_str = ''.join([str(int(let1) ^ int(let2)) for let1, let2 in zip(binary1, binary2)])
ascii_char = chr(int(bit_str, 2))
ascii_char


# # <CENTER>PRE-ENCRYPT 

# In[62]:


def xor_encrypt(message):
    num_list = [ord(char) for char in message]
    key = secrets.choice(range(128))
    encrypt_list = [num ^ key for num in num_list]
    return [''.join([num.to_bytes((num.bit_length() + 7) // 8, 'big').decode() for num in encrypt_list]), key]


# In[63]:


orig = 'socorro_deus!'
orig


# In[64]:


string.ascii_letters


# In[65]:


quatschteste = random.choice(string.ascii_letters)
quatschteste


# In[66]:


message = random.choice(string.ascii_letters) + random.choice(string.ascii_letters) + random.choice(string.ascii_letters) + 'socorro_deus!' + random.choice(string.ascii_letters) + random.choice(string.ascii_letters) + random.choice(string.ascii_letters)
message


# In[67]:


num_list = [ord(char) for char in message]
num_list


# In[68]:


num_list = [ord(char) for char in message]
key = secrets.choice(range(128))
encrypt_list = [num ^ key for num in num_list]
''.join([num.to_bytes((num.bit_length() + 7) // 8, 'big').decode() for num in encrypt_list])


# In[69]:


key


# In[70]:


encrypt_list


# # <CENTER> ENCRYPT XOR

# In[71]:


cipher = xor_encrypt(message)


# In[72]:


ct = cipher[0]
key = cipher[1]


# In[73]:


ct


# In[74]:


key


# In[75]:


cipher


# # <CENTER> DECRYPT XOR

# In[76]:


def xor_decrypt(cipher_text, key):
    num_list = [ord(char) ^key for char in cipher_text]
    return ''.join([num.to_bytes((num.bit_length() + 7) // 8, 'big').decode() for num in num_list])


# In[77]:


ct


# In[78]:


key


# In[79]:


result = xor_decrypt(ct, key)
result


# In[80]:


result == message


# In[81]:


result2 = result[3:16]
result2


# In[82]:


result2 == orig


# # <center> AES
# 
# Setup:
# 
# 
# >() Um cipher é um algoritmo que executa criptografia ou descriptografia, mediante uma série de etapas bem definidas que podem ser seguidos como um procedimento.<br>
# ()Utilizamos um algoritmo de criptografia denominado AES.<br>
# ()O modo de operação para cifras de bloco é o Cipher Block Chaining(CBC). Este modo de operação é criado utilizando um vetor de inicilização(tipo uma segunda chave de criptografia).
# 
# Com o AES, uma chave e comprimento específico(por exemplo, 128, 192 e 256 bits) é utilizada para criptografar e descriptografar um bloco de mensagens. Cada cipher criptografa e descriptografa dados em blocos de "x"bits usando chaves criptográficas de tamanho pré-definido. Neste tipo de algoritmo, as chaves de criptografia são simétricas, isto é, a mesma chave é utilizada para criptografar e descriptografar. Assim, ambos os lados (remetente e destinatário) devem conhecer e utilizar a mesma chave secreta.

# ![5E4C62AB-40B3-4F6E-ABA3-C022E8BE61C5.jpeg](attachment:5E4C62AB-40B3-4F6E-ABA3-C022E8BE61C5.jpeg)

# ![155951BF-0852-4AF4-B585-07FD62247155_1_201_a.jpeg](attachment:155951BF-0852-4AF4-B585-07FD62247155_1_201_a.jpeg)

# In[138]:


import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# In[139]:


backend = default_backend()


# In[140]:


key = os.urandom(16)
key


# In[141]:


# Vetor de inicialização
iv = os.urandom(16)
iv


# In[142]:


string.ascii_letters


# In[143]:


quatschteste = random.choice(string.ascii_letters)
quatschteste


# In[144]:


MSG = random.choice(string.ascii_letters) + random.choice(string.ascii_letters) + random.choice(string.ascii_letters) + "O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma.O rato roeu a roupa do rei de roma." + random.choice(string.ascii_letters) + random.choice(string.ascii_letters) + random.choice(string.ascii_letters)


# In[145]:


MSG


# In[146]:


# Criptografia
# Converter em bytes

b_MSG = bytearray(MSG, encoding="ascii") # Mensagem tem que ser byte array


# In[147]:


# Adequar o tamanho da mensagem original para que seja multipla de block_size
block_size = 16
n = len(b_MSG)
spaces_add = block_size - n % block_size # Calcular a quantidade de espaços que vamos adicionar ao final da msg
new_b_MSG = bytearray(MSG + ' ' * spaces_add, encoding="utf8")
# 1. - Criamos o objeto que criptografa AES com a chave gerada
aes = algorithms.AES(key)
# 2. - Criamos o modo como o vetor de inicialização criado
cbc = modes.CBC(iv)
# 3. - Criamos o cipher
cipher = Cipher(aes, cbc, backend=backend)
# Obtemos o encriptador a partir do cipher
encryptor = cipher.encryptor()
# Tentar encryptar
ct = encryptor.update(new_b_MSG) + encryptor.finalize()


# In[148]:


ct


# In[149]:


# 1 Obter descriptador
decryptor = cipher.decryptor()


# In[150]:


# 1 Decriptar mensagem
decryptor.update(ct) + decryptor.finalize()


# In[ ]:





# # <center> KMP ALGORITMO

# ![17DB12C3-C74B-464B-8B78-757D74ACBE06.jpeg](attachment:17DB12C3-C74B-464B-8B78-757D74ACBE06.jpeg)

# In[1]:


# Python program for KMP Algorithm
def KMPSearch(pat, txt):
	M = len(pat)
	N = len(txt)

	# create lps[] that will hold the longest prefix suffix
	# values for pattern
	lps = [0]*M
	j = 0 # index for pat[]

	# Preprocess the pattern (calculate lps[] array)
	computeLPSArray(pat, M, lps)

	i = 0 # index for txt[]
	while i < N:
		if pat[j] == txt[i]:
			i += 1
			j += 1

		if j == M:
			print("Found pattern at index " + str(i-j))
			j = lps[j-1]

		# mismatch after j matches
		elif i < N and pat[j] != txt[i]:
			# Do not match lps[0..lps[j-1]] characters,
			# they will match anyway
			if j != 0:
				j = lps[j-1]
			else:
				i += 1

def computeLPSArray(pat, M, lps):
	len = 0 # length of the previous longest prefix suffix

	lps[0] # lps[0] is always 0
	i = 1

	# the loop calculates lps[i] for i = 1 to M-1
	while i < M:
		if pat[i]== pat[len]:
			len += 1
			lps[i] = len
			i += 1
		else:
			# This is tricky. Consider the example.
			# AAACAAAA and i = 7. The idea is similar
			# to search step.
			if len != 0:
				len = lps[len-1]

				# Also, note that we do not increment i here
			else:
				lps[i] = 0
				i += 1

txt = "OalvinegrodavilabelmiroosantostimedomeucoracaoEhomotivodetodomeurisoeminhaslagrimasdeemocao.Suabandeiradomantoehahistoriadeumpassadoeumpresentesodegloriasnascerviverenosantosmorrerehumorgulhoquenemtodospodemter."
pat = "alvinegrodavilabelmiro"
KMPSearch(pat, txt)

# This code is contributed by Bhavya Jain


# In[ ]:




