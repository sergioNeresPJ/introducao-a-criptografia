package rc4;

import java.util.*;


public class rc4 {
    public static void main(String args[]) throws InterruptedException{
        System.out.print("Insira o texto cifrado em hexadecimal: ");
        Scanner input = new Scanner(System.in);
        String hexa = input.nextLine();
        String texto = "";
        int i = 0;
        int j = 0;
        for(i=0, j=2; j<=hexa.length();i+=2,j+=2){
            int decimal = hexadecimalToDecimal(hexa.substring(i, j));
            char temp = (char)decimal;
            texto += temp;
            //System.out.println(hexa.substring(i, j) + " -> " + decimal + " -> " + temp);
            //System.out.println(texto);
            //Thread.sleep(1500);
        }

        System.out.print("Insira a chave que será usada: ");
        String chaveString = input.nextLine();
        int chave[] = new int[chaveString.length()];
        for(i=0; i<chaveString.length(); i++)
            chave[i] = chaveString.charAt(i);

        int s[] = new int[256];
        for(i=0; i<256; i++)
            s[i]=i;

    
        for(j=0, i=0;i<256; i++){
            j = (j + s[i] + chave[i%chaveString.length()]) % 256;
            int temp = s[i];
            s[i] = s[j];
            s[j] = temp;
        }

        /*for(int i=0;i<256; i++){
            System.out.print(s[i] + " ");
            if(i%10 == 0) System.out.println();
        }*/

        String mensagemHex = "";
        char[] mensagemChar = new char[texto.length()];
        j=0;
        i=0;
        for(int cont=0; cont<texto.length(); cont++){
            i = (i+1) % 256;
            j = (j + s[i]) % 256;
            int temp = s[i];
            s[i] = s[j];
            s[j] = temp;

            int k = (s[(s[i]+s[j])%256]);
            //System.out.println((s[(s[i]+s[j])%256]) + " -> " + k);
            //System.out.println((int)texto.charAt(cont) + " -> " + texto.charAt(cont));
            //System.out.print(k + " ^ " + texto.charAt(cont));
            int c = (k ^ (int)texto.charAt(cont));
            //System.out.println(" = " + c + "(hex: " + Integer.toHexString((int)c) + ")");
            //System.out.println();
            if(c<16)
                mensagemHex += '0';
            mensagemHex += Integer.toHexString(c);
            mensagemChar[cont] = (char)c;
            //Thread.sleep(1500);
        }

        System.out.println("A mensagem decifrada em hexadecimal é (100% confiavel): " + mensagemHex);
        System.out.println();

        System.out.println("A mensagem decifrada em formato de String é (pode ser que haja erros na conversão para ASCII): ");
        for(int cont=0; cont<mensagemChar.length; cont++)
            System.out.print(mensagemChar[cont]);
        input.close();
    }


    public static int hexadecimalToDecimal(String hexa) {
        hexa = hexa.toUpperCase();
        int size = hexa.length();
        int result = 0;
        for (int i = 0; i < hexa.length(); i++) {
            switch (hexa.charAt(i)) {
                case '0':
                    result += (0 * Math.pow(16, --size));
                    break;

                case '1':
                    result += (1 * Math.pow(16, --size));
                    break;
                case '2':
                    result += (2 * Math.pow(16, --size));
                    break;
                case '3':
                    result += (3 * Math.pow(16, --size));
                    break;
                case '4':
                    result += (4 * Math.pow(16, --size));
                    break;
                case '5':
                    result += (5 * Math.pow(16, --size));
                    break;
                case '6':
                    result += (6 * Math.pow(16, --size));
                    break;
                case '7':
                    result += (7 * Math.pow(16, --size));
                    break;
                case '8':
                    result += (8 * Math.pow(16, --size));
                    break;
                case '9':
                    result += (9 * Math.pow(16, --size));
                    break;
                case 'A':
                    result += (10 * Math.pow(16, --size));
                    break;
                case 'B':
                    result += (11 * Math.pow(16, --size));
                    break;
                case 'C':
                    result += (12 * Math.pow(16, --size));
                    break;
                case 'D':
                    result += (13 * Math.pow(16, --size));
                    break;
                case 'E':
                    result += (14 * Math.pow(16, --size));
                    break;
                case 'F':
                    result += (15 * Math.pow(16, --size));
            }
        }

       return result;
    }
}
