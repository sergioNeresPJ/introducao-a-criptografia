/* ==========================================================================
 * Universidade Federal de São Carlos - Campus Sorocaba
 * Disciplina: Introducao à Criptografia
 * Profª Yeda
 *
 * Trabalho AES
 *
 * RA: 801814
 * Aluno: Sergio Neres Pereira Junior
 * ==========================================================================
 *                            ANTES DE COMPILAR
 * O programa funciona para chaves de 128, 192 ou 256 bits. Entretanto, seu bom funcionamento está condicionado às
 * primeiras linhas de código (#define). Os "define"s que não condizerem com o seu objetivo deverão ser comentados.
 * Ex:
 * Se a sua chave é de 128 bits, as primeiras linhas de código deverão estar assim:
 * // #define AES256 1
 * // #define AES192 1
 * #define AES128 1
 * 
 *                            INSTRUÇÕES PARA COMPILAÇÃO
 * Para compilar, basta digitar gcc aes.c no terminal
 * Logo após, será gerado um executável na pasta onde está localizado o arquivo .c
 * Executando esse arquivo, você  terá acesso ao cifrador AES
 * 
 * 
 *                             INSTRUÇÕES PARA EXECUÇÃO
 * Agora, com o programa em execução, será solicitado primeiramente o texto claro a ser cifrado.
 * (Vale ressaltar que a mensagem deve ser de 128 bits).
 * Logo após, será solicitado a chave, cujo tamanho segue o definido conforme o primeiro passo.
 * Por fim, você informa 1 caso queira ver o passo a passo ou 0 caso queira a mensagem cifrada de forma direta.
 * Você pode verificar a veracidade da cifragem conferindo em https://www.cryptool.org/en/cto/aes-step-by-step
 * ========================================================================== */

#include <stdio.h>
#include <stdlib.h>

//#define AES256 1
//#define AES192 1
#define AES128 1

#define TAM_MX 16
#define TAM_SBOX 256
#define TAM_RCON 32
#define POLINOMIO_REDUTOR 0x11b

#if defined(AES256) && (AES256 == 1)
    #define TAM_CHAVE 32
    #define QTD_SUBCHAVES 60
    #define Nk 8
    #define Nr 14
#elif defined(AES192) && (AES192 == 1)
    #define TAM_CHAVE 24
    #define QTD_SUBCHAVES 52
    #define Nk 6
    #define Nr 12
#else
    #define TAM_CHAVE 16
    #define QTD_SUBCHAVES 44
    #define Nk 4
    #define Nr 10
#endif


const int rcon[TAM_RCON] = {
  //0     1    2      3     4    5     6     7      8    9     10
  0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

const int sbox[TAM_SBOX] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };
  
const int mix_columns_mx[TAM_MX] = {
  0x02, 0x03, 0x01, 0x01,
  0x01, 0x02, 0x03, 0x01,
  0x01, 0x01, 0x02, 0x03,
  0x03, 0x01, 0x01, 0x02};


//funcoes para geracao de subchaves
void gera_subchaves(int *chave, int *subchaves);
void rot_word(int *w);
void sub_word(int *w);
void xor_com_rcon(int *w, int i);

//funcoes principais
void atualiza_subchaves_mx(int round, int *subchaves_mx, int *subchaves);
void add_round_key(int *estado_mx, int *subchaves_mx);
void sub_bytes(int *estado_mx);
void shift_rows(int *estado_mx);
void mix_columns(int *estado_mx);

//funcoes complementares
void estado_mx_para_texto_cifrado(int *estado_mx, int *texto_cifrado);
void imprimir_mx(int *mx);


int main(){
    int mensagem[TAM_MX];
    int estado_mx[TAM_MX];
    int subchaves[QTD_SUBCHAVES*Nk];
    int subchaves_mx[TAM_MX];
    int texto_cifrado[TAM_MX];  
    int chave[TAM_CHAVE];

    printf("Insira a mensagem para ser criptografada em HEXADECIMAL (contendo 16 bytes):\n");
    for(int i=0; i<TAM_MX;i++)
      scanf("%2x",&mensagem[i]);
    printf("\n");

    printf("Insira a a chave que será usada para criptografar no formato HEXADECIMAL:\n");
    for(int i=0; i<TAM_MX;i++)
      scanf("%2x",&chave[i]);
    printf("\n");
    
    gera_subchaves(chave, subchaves);

    int escolha;
    printf("Voce deseja ver o passo a passo? (1- SIM, 2- NAO)");
    scanf("%d", &escolha);

    for(int i=0; i<4; i++){
      estado_mx[i*4] = mensagem[i];
      estado_mx[i*4+1] = mensagem[i+4];
      estado_mx[i*4+2] = mensagem[i+8];
      estado_mx[i*4+3] = mensagem[i+12];
    }

    if(escolha==1){
      for(int round = 1; round<=Nr; round++){
        printf("\n\n\n-----------------------ROUND %d-----------------------\n", round);
        printf("Matriz estado inicial: ");imprimir_mx(&estado_mx);
        sub_bytes(&estado_mx);
        printf("Apos sub_bytes: ");imprimir_mx(&estado_mx);
        shift_rows(&estado_mx);
        printf("Apos shift_rows: ");imprimir_mx(&estado_mx);
        if(round != Nr){
          mix_columns(&estado_mx);
          printf("Apos mix_columns: ");imprimir_mx(&estado_mx);
        }
        atualiza_subchaves_mx(round, &subchaves_mx, &subchaves);
        add_round_key(&estado_mx, &subchaves_mx);
        printf("Apos add_round_key: ");imprimir_mx(&estado_mx);
        //sleep(5);
      }
    }else{
      for(int round = 1; round<=Nr; round++){
        sub_bytes(&estado_mx);
        shift_rows(&estado_mx);
        if(round != Nr)
          mix_columns(&estado_mx);
        atualiza_subchaves_mx(round, &subchaves_mx, &subchaves);
        add_round_key(&estado_mx, &subchaves_mx);
      }
    }

    estado_mx_para_texto_cifrado(&estado_mx, &texto_cifrado);


    printf("Seu texto cifrado em AES:\n");
    for(int i=1; i<=TAM_MX; i++){
      if(texto_cifrado[i-1]<16)
        printf("0");
      printf("%x ", texto_cifrado[i-1]);
    }


    system("pause");
    return 0;
}

void gera_subchaves(int *chave, int *subchaves){
  int i;

    for(i=0;i<Nk; i++){
        subchaves[i] = chave[i];
        subchaves[i+4] = chave[i+4];
        subchaves[i+8] = chave[i+8];
        subchaves[i+12] = chave[i+12];
        if(Nk>4){
          subchaves[i+16] = chave[i+16];
          subchaves[i+20] = chave[i+20];
          if(Nk>6){
            subchaves[i+24] = chave[i+24];
            subchaves[i+28] = chave[i+28];
          }
        }
  }

  for(i=Nk; i < QTD_SUBCHAVES; i++){

      int temp[TAM_CHAVE/Nk];
      for(int cont=0; cont < TAM_CHAVE/Nk; cont++)
        temp[cont] = subchaves[(i-1)*4 + cont];

      
      if(i%Nk == 0){
        rot_word(temp);
        sub_word(&temp);
        xor_com_rcon(&temp, i);
      }

      if((Nk == 8) && (i%Nk == Nk/2))
        sub_word(&temp);

      for(int j=0;j<(TAM_CHAVE/Nk); j++)
        subchaves[i*4 + j] = temp[j] ^ subchaves[(i-Nk)*4 + j];
    }
}

void rot_word(int *w){
  int temp = w[0]; 
  w[0] = w[1];
  w[1] = w[2];
  w[2] = w[3];
  w[3] = temp;
}

void sub_word(int *w){
  for(int i=0;i<TAM_CHAVE/Nk;i++)
    w[i] = sbox[w[i]];
}

void xor_com_rcon(int *w, int i){
  int temp = rcon[i/Nk];
  w[0] = w[0] ^ temp;
}



void atualiza_subchaves_mx(int round, int *subchaves_mx, int *subchaves){
  for(int i=0; i<4; i++){
    subchaves_mx[i] = subchaves[(round*4)*4 + i*4];
    subchaves_mx[i+4] = subchaves[(round*4)*4 + i*4 + 1];
    subchaves_mx[i+8] = subchaves[(round*4)*4 + i*4 + 2];
    subchaves_mx[i+12] = subchaves[(round*4)*4 + i*4 + 3];
  }
}

void add_round_key(int *estado_mx, int *subchaves_mx){
  for(int i=0; i<TAM_MX; i++){
    (estado_mx[i]) ^= subchaves_mx[i];
  }
}

void sub_bytes(int *estado_mx){
  for(int i=0;i<TAM_MX;i++)
    estado_mx[i] = sbox[estado_mx[i]];
}

void shift_rows(int *estado_mx){
  int temp;
  //muda segunda linha
  temp = estado_mx[4];
  estado_mx[4] = estado_mx[5];
  estado_mx[5] = estado_mx[6];
  estado_mx[6] = estado_mx[7];
  estado_mx[7] = temp;

  //muda terceira linha
  temp = estado_mx[11];
  estado_mx[11] = estado_mx[9];
  estado_mx[9] = temp;
  temp = estado_mx[10];
  estado_mx[10] = estado_mx[8];
  estado_mx[8] = temp;

  //muda quarta linha
  temp = estado_mx[15];
  estado_mx[15] = estado_mx[14];
  estado_mx[14] = estado_mx[13];
  estado_mx[13] = estado_mx[12];
  estado_mx[12] = temp;
}

void mix_columns(int *estado_mx){
  int multiplicacao, resultado_xors;
  int aux[TAM_MX/4];
  for(int i=0;i<TAM_MX/4; i++){//iterarador para colunas na matriz estado
    for(int j=0; j<TAM_MX/4; j++){//iterador linha da matriz padrao
      resultado_xors = 0;//guarda os resultado dos xors a cada iteracao
      for(int k=0; k< TAM_MX/4; k++){//iterador para coluna na matriz padrão e linha na matriz estado
        if(mix_columns_mx[j*4 + k] == 3)//(x¹+1) * (polinomio y) = (x¹)*(polinomio y) XOR (1)*(polinomio y)
          multiplicacao = (2 * estado_mx[k*4 + i]) ^ (1 * estado_mx[k*4 + i]);
        else
          multiplicacao = mix_columns_mx[j*4 + k] * estado_mx[k*4 + i];

        if(multiplicacao > 255)
          multiplicacao ^= (POLINOMIO_REDUTOR);
        
        if(k==0)//resultado_xors==0 (primeira iteracao)
          resultado_xors = multiplicacao;
        else
          resultado_xors ^= multiplicacao;
      }
      aux[j] = resultado_xors;
    }
  estado_mx[i]    = aux[0];
  estado_mx[i+4]  = aux[1];
  estado_mx[i+8]  = aux[2];
  estado_mx[i+12] = aux[3];
  }
}

void estado_mx_para_texto_cifrado(int *estado_mx, int *texto_cifrado){
  texto_cifrado[0] =  estado_mx[0];
  texto_cifrado[1] =  estado_mx[4];
  texto_cifrado[2] =  estado_mx[8];
  texto_cifrado[3] =  estado_mx[12];
  texto_cifrado[4] =  estado_mx[1];
  texto_cifrado[5] =  estado_mx[5];
  texto_cifrado[6] =  estado_mx[9];
  texto_cifrado[7] =  estado_mx[13];
  texto_cifrado[8] =  estado_mx[2];
  texto_cifrado[9] =  estado_mx[6];
  texto_cifrado[10] = estado_mx[10];
  texto_cifrado[11] = estado_mx[14];
  texto_cifrado[12] = estado_mx[3];
  texto_cifrado[13] = estado_mx[6];
  texto_cifrado[14] = estado_mx[11];
  texto_cifrado[15] = estado_mx[15];
}

void imprimir_mx(int *mx){
  printf("\n");
  for(int i=0; i< TAM_MX; i++){
    printf("%2x ", mx[i]);
    if((i+1)%4==0)
      printf("\n");
  }
  printf("\n");
}