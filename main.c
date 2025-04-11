#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

// AES-128 key for encryption and decryption (should be properly secured in production)
// Note: Using a hardcoded key is insecure - consider using a key derivation function
const unsigned char aes_key[] = "0123456789abcdef";

// Helper function to print OpenSSL errors
void print_openssl_error() {
    unsigned long err;
    while ((err = ERR_get_error())) {
        fprintf(stderr, "OpenSSL error: %s\n", ERR_error_string(err, NULL));
    }
}

//character alphabet of table base64
const unsigned char character_alphabet[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

//all functions used
void encrypt_decrypt_file(const char*,const char*);
unsigned char* encode(unsigned const char*);
unsigned char* decode(unsigned const char*);

//principal function
int main(int argc,char **argv){
    if(argc == 3) {
        if (!strcmp(argv[1], "encrypt")) {
            encrypt_decrypt_file(argv[2], "encrypt");
        }
        else if(!strcmp(argv[1], "decrypt")) {
            encrypt_decrypt_file(argv[2], "decrypt");
        }
        else {
            fprintf(stderr, "Error: Invalid option. Use 'encrypt' or 'decrypt'\n");
            return 1;
        }
    } else {
        fprintf(stderr, "Error: Invalid arguments\nUsage: %s [encrypt|decrypt] filename\n", argv[0]);
        return 1;
    }
    return 0;
}
void encrypt_decrypt_file(const char* path,const char* option){
    FILE *file = NULL;
    if((file = fopen(path, "rb")) == NULL) {
        fprintf(stderr, "Error: Cannot open file '%s' for reading\n", path);
        exit(EXIT_FAILURE);
    }
    fseek(file,0,SEEK_END);
    size_t length_data = ftell(file);
    rewind(file);

    unsigned char *aes_input = (unsigned char *)malloc(sizeof(unsigned char) * length_data + 1);
    if(aes_input == NULL) {
        fclose(file);
        fprintf(stderr, "Error: Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    int i = 0;
    while(i < length_data) {
        int ch = getc(file);
        if(ch == EOF) {
            free(aes_input);
            fclose(file);
            fprintf(stderr, "Error: Unexpected end of file\n");
            exit(EXIT_FAILURE);
        }
        aes_input[i] = (unsigned char)ch;
        ++i;
    }
    rewind(file);i=0;
    *(aes_input+length_data)='\0';

    if(!strcmp(option,"encrypt")){
        //(AES- 128,AES-192,AES-256)bit
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            print_openssl_error();
            free(aes_input);
            fclose(file);
            exit(EXIT_FAILURE);
        }

        //init vector
        unsigned char iv[EVP_MAX_IV_LENGTH+1];
        memset(iv, 0x00, EVP_MAX_IV_LENGTH);
        iv[EVP_MAX_IV_LENGTH]='\0';

        // Initialize encryption
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, aes_key, iv)) {
            print_openssl_error();
            EVP_CIPHER_CTX_free(ctx);
            free(aes_input);
            fclose(file);
            exit(EXIT_FAILURE);
        }

        //buffer for encryption
        size_t length_enc_out = length_data + EVP_CIPHER_CTX_block_size(ctx);
        unsigned char *enc_out = (unsigned char *)malloc(sizeof(unsigned char)* length_enc_out);
        if (!enc_out) {
            EVP_CIPHER_CTX_free(ctx);
            free(aes_input);
            fclose(file);
            fprintf(stderr, "Error: Memory allocation failed\n");
            exit(EXIT_FAILURE);
        }

        int out_len;
        // Perform encryption
        if (1 != EVP_EncryptUpdate(ctx, enc_out, &out_len, aes_input, length_data)) {
            print_openssl_error();
            EVP_CIPHER_CTX_free(ctx);
            free(enc_out);
            free(aes_input);
            fclose(file);
            exit(EXIT_FAILURE);
        }

        int final_len;
        if (1 != EVP_EncryptFinal_ex(ctx, enc_out + out_len, &final_len)) {
            print_openssl_error();
            EVP_CIPHER_CTX_free(ctx);
            free(enc_out);
            free(aes_input);
            fclose(file);
            exit(EXIT_FAILURE);
        }
        length_enc_out = out_len + final_len;

    // Securely clear sensitive data from memory
    if(aes_input) {
        memset(aes_input, 0, length_data);
        free(aes_input);
    }

    //reopen the file to clean it
    fclose(file);
    file = fopen(path,"w");
    length_data=0;

    //we can not save the result on the file in binary format because sometimes the result can contain a character with a null ASCII value, and it will lose the encrypted result on the file bacause when printf a '%s' the printf will stop in the first zero ASCII value value and then the others where is go?? ;) that is why we formatted the result in hexadecimal on a temporary file then we recover this result in format base64 then we store this final result on the final file.
     FILE *temporary_file=tmpfile();

     for(i=0; i<length_enc_out; i++){
        fprintf(temporary_file,"0x%02x",*(enc_out+i));
        length_data+=5;
     }
    i=0;rewind(temporary_file);

    unsigned char *aes_input_base64 = (unsigned char *)malloc(sizeof(unsigned char)*(length_data+1));
    while(i<length_data){
        *(aes_input_base64+i)=getc(temporary_file);
        ++i;
    }
    *(aes_input_base64+length_data)='\0';

    fprintf(file,"%s",encode(aes_input_base64));

    fclose(temporary_file);

    free(aes_input_base64);

    //verbose(enc_out formatted in hexadecimal)
    //for(int i=0; i<length_enc_out; i++)  printf("-%d --> %02x\n",i,*(enc_out +i));

    if(enc_out) {
        memset(enc_out, 0, length_enc_out);
        free(enc_out);
    }
    }

    else if (!strcmp(option,"decrypt")){
    //to change format the aes_input: base64 --> hex --> binary    

    FILE *temporary_file=tmpfile();
    fprintf(temporary_file,"%s",decode(aes_input));
    rewind(temporary_file);

    //clear aes_input to store on it binary context
    memset(aes_input,0x00,length_data);
    length_data=0;

    //aes_input content a binary context
    while(1){
        int in;
        if (feof(temporary_file))break;
        fscanf(temporary_file,"0x%x",&in);
        *(aes_input+length_data)=(char)in;
        length_data++;
    }
    fclose(temporary_file);

        //(Aes-128,AES-192,AES-256)bit
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            print_openssl_error();
            free(aes_input);
            fclose(file);
            exit(EXIT_FAILURE);
        }

        //init vector
        unsigned char iv[EVP_MAX_IV_LENGTH+1];
        memset(iv,0x00,EVP_MAX_IV_LENGTH);
        iv[EVP_MAX_IV_LENGTH]='\0';

        // Initialize decryption
        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, aes_key, iv)) {
            print_openssl_error();
            EVP_CIPHER_CTX_free(ctx);
            free(aes_input);
            fclose(file);
            exit(EXIT_FAILURE);
        }

        //buffer for decryption
        unsigned char *dec_out = (unsigned char *)malloc(sizeof(unsigned char)*length_data);
        if (!dec_out) {
            EVP_CIPHER_CTX_free(ctx);
            free(aes_input);
            fclose(file);
            fprintf(stderr, "Error: Memory allocation failed\n");
            exit(EXIT_FAILURE);
        }

        int out_len;
        // Perform decryption
        if (1 != EVP_DecryptUpdate(ctx, dec_out, &out_len, aes_input, length_data)) {
            print_openssl_error();
            EVP_CIPHER_CTX_free(ctx);
            free(dec_out);
            free(aes_input);
            fclose(file);
            exit(EXIT_FAILURE);
        }

        int final_len;
        if (1 != EVP_DecryptFinal_ex(ctx, dec_out + out_len, &final_len)) {
            print_openssl_error();
            EVP_CIPHER_CTX_free(ctx);
            free(dec_out);
            free(aes_input);
            fclose(file);
            exit(EXIT_FAILURE);
        }

    free(aes_input);

    //reopen the file to clean it
    fclose(file);
    file=fopen(path,"w");

    fprintf(file,"%s",dec_out);

    //verbose(dec_out foematted in hexadecimal)
    //for(int i=0; i<strlen((char*)dec_out);i++)  printf("-%d --> %c\n",i,*(dec_out +i));

    EVP_CIPHER_CTX_free(ctx);
    free(dec_out);
}
else{
    printf("bad options");
}

fclose(file);
}
/**
 * Encodes binary data to Base64 format
 * @param string Input binary data to encode
 * @return Pointer to allocated buffer containing Base64 string
 * @note Caller must free the returned pointer
 */
unsigned char* encode(unsigned const char* string) {
	//get length of string
	int length_of_string = 0;
	while(string[length_of_string] != '\0')	length_of_string++;

	int number_of_binary = length_of_string * 8; //multiplication by 8 so that each one character is represent on 8 bits

	//padding to complete the 6 bits when using base table 64
	int padding=0;

	while(1){
        if(number_of_binary % 6 == 0)	break;
        padding++;
        number_of_binary++;
    }

	unsigned char* encode_data = (unsigned char*)malloc(sizeof(unsigned char) * ((number_of_binary / 6) + (padding / 2))); //after the encoding each 6 bits will present a one character

	//pointer to store all bits and calloc just to initialize frame with 0
	int* store_result_binary = (int*)calloc(sizeof(int) , number_of_binary);

	//Jumping (8 bits) during when store bits in pointer
	int z_index = 8;

	for(int i=0;i<length_of_string;i++){
		int index = z_index;
		int quotien = string[i];

		while(1){
			if(quotien / 2){
				*(store_result_binary + (--index)) = quotien % 2;
				quotien /=  2;
			}else{
			*(store_result_binary + (--index)) = quotien % 2;
			break;
			}
		}

		index = z_index += 8;

	}
	//to see ASCII to binary + padding
	//for(int i=0;i<number_of_binary;i++)	printf("%d%s",*(store_result_binary + i),(i+1)%8 ? "" : " ");
	//printf("\n");

	//6-bits to decimal
	int index = number_of_binary / 6;
	for(int i=(number_of_binary -1); i>0 ; i -= 6){
		int j=0,power=0;
		double _6bit=0;
		while(j<6){
			if(*(store_result_binary + (i - j)) == 1 ){
				int powe=1;
				for(int k=0; k<power; k++){
					powe *= 2;
				}
				_6bit += powe;
			}
			power++;
			j++;
		}

		*(encode_data + (--index)) = *(character_alphabet + (int)_6bit);
	}

	//adding = (just for padding)
	if(padding == 2)
		*(encode_data + (number_of_binary / 6)) = '=';
	if(padding == 4){
		*(encode_data + (number_of_binary / 6)) = '=';
		*(encode_data + (number_of_binary / 6) + 1) = '=';
	}
	*(encode_data + ((number_of_binary / 6) + (padding / 2))) = '\0';
	//to see the encoding
	//for(int i=0; i<((number_of_binary / 6) + (padding / 2)) ;i++)	printf("-%d %02x\n",i,*(encode_data + i));

	//free pointers
	free(store_result_binary);
	store_result_binary=NULL;

	return encode_data;
}

/**
 * Decodes Base64 data back to binary format
 * @param string Base64 encoded string to decode
 * @return Pointer to allocated buffer containing binary data
 * @note Caller must free the returned pointer
 */
unsigned char* decode(unsigned const char* string) {

	//get length of string
	int length_of_string = 0;
	while(string[length_of_string] != '\0')	length_of_string++;

	//find the number of repetition of the letter '='
	int padding=0;
	int i=0;
	while(i < length_of_string){
		if(string[i] == '=')	++padding;
		i++;
	}

	int number_of_binary = ((length_of_string - padding) * 6) - (padding * 2);
	unsigned char* decode_data = (unsigned char*)malloc(sizeof(unsigned char) * (number_of_binary / 8) + 1);

	//pointer to store all bits and calloc just to initialize frame with 0
	int* store_result_binary = (int*)calloc(sizeof(int) , number_of_binary * 8);

	//Jumping (6 bits) during when store bits in pointer
	int z_index = 6;

	for(int i=0;i<(length_of_string - padding);i++){
		int index = z_index;
		int quotien = 0;
		for(int j=0; j < 64; j++){
			if(string[i] == character_alphabet[j]){
				quotien = j;
				break;
			}
		}
		while(1){
			if(quotien / 2){
				*(store_result_binary + (--index)) = quotien % 2;
				quotien /=  2;
			}else{
			*(store_result_binary + (--index)) = quotien % 2;
			break;
			}
		}

		index = z_index += 6;

	}

	//to see base64 to binary without padding
	//for(int i=0;i<number_of_binary;i++)	printf("%d%s",*(store_result_binary + i),(i+1)%8 ? "" : " ");
	//printf("\n");

	//8-bits to decimal
	int index = 0;

	for(int i=0; i<number_of_binary ; i += 8){
		int j=7,power=0;
		double _8bit=0;
		while(j>=0){
			if(*(store_result_binary + (i + j)) == 1 ){
				int powe=1;
				for(int k=0; k<power; k++){
					powe *= 2;
				}
				_8bit += powe;
				powe=0;
			}
			power++;
			j--;
		}
		*(decode_data + (index++)) = (int)_8bit;
		j=7;power=0;_8bit=0;
	}
	*(decode_data + (number_of_binary / 8) + 1) = '\0';

	//to see the decoding
	//for(int i=0; i<(number_of_binary / 8) ;i++)	printf("-%d %02x\n",i,*(decode_data + i));

	//free pointers
	free(store_result_binary);
	store_result_binary=NULL;

	return decode_data;
}
//gcc -o main main.c -lssl -lcrypto
//./main encrypt test.txt
//./main decrypt test.txt
//./main encrypt test.txt
//./main decrypt test.txt
//./main encrypt test.txt
//./main decrypt test.txt
//./main encrypt test.txt