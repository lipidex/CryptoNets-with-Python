#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <chrono>
#include <random>
#include <thread>
#include <mutex>
#include <random>
#include <limits>
#include <math.h>
#include "seal/seal.h"
#include <fstream>

#include <filesystem>

using namespace std;
using namespace seal;

// PARAMETERS
EncryptionParameters *parms[5];
std::vector<Modulus> q_array;
SEALContext *context[5];
// KEYS
KeyGenerator *keygen[5];
SecretKey secret_key[5];
// OBJECTS
Encryptor *encryptor[5];
Decryptor *decryptor[5];
Evaluator *evaluator[5];
BatchEncoder *crtbuilder[5];
int plain_poly_size = 0;
int enc_poly_size = 0;
// CONFIG
size_t poly_modulus_degree = 4096;

void deallocate_() {
	for (int i=0; i<5; i++) {
		delete parms[i];
	}
	for (int i=0; i<5; i++) {
		delete context[i];
	}
	for (int i=0; i<5; i++) {
		delete keygen[i];
	}
	for (int i=0; i<5; i++) {
		delete encryptor[i];
	}
	for (int i=0; i<5; i++) {
		delete decryptor[i];
	}
	for (int i=0; i<5; i++) {
		delete evaluator[i];
	}
	for (int i=0; i<5; i++) {
		delete crtbuilder[i];
	}
}

void generate_new_keys_() {
	PublicKey public_key[5]; //TODO: da rispostare in un modo o nell'altro come globale
	RelinKeys ev_keys[5];

	// PARAMETERS
	q_array = CoeffModulus::BFVDefault(poly_modulus_degree); // 128 is implicit

	for (int i=0; i<5; i++) {
		parms[i] = new EncryptionParameters(scheme_type::bfv);
	}

	// --t
	parms[0]->set_plain_modulus(40961);
	parms[1]->set_plain_modulus(65537);
	parms[2]->set_plain_modulus(114689);
	parms[3]->set_plain_modulus(147457);
	parms[4]->set_plain_modulus(188417);

	std::string file_name = "";
	for (int i=0; i<5; i++) {
		// --n
		parms[i]->set_poly_modulus_degree(poly_modulus_degree);
		// --q
		parms[i]->set_coeff_modulus(q_array);

		context[i] = new SEALContext(*parms[i]);

		// STORE KEYS
		keygen[i] = new KeyGenerator(*context[i]);
		keygen[i]->create_public_key(public_key[i]);
		secret_key[i] = keygen[i]->secret_key();
		keygen[i]->create_relin_keys(ev_keys[i]); // per rilinearizzare dopo lo square
		// --public
		file_name = "./keys/public-" + std::to_string(i);
		std::ofstream pk_stream(file_name, std::ios::out | std::ios::trunc | std::ios::binary);
		public_key[i].save(pk_stream);
		pk_stream.close();
		// --secret
		file_name = "./keys/secret-" + std::to_string(i);
		std::ofstream sk_stream(file_name, std::ios::out | std::ios::trunc | std::ios::binary);
		secret_key[i].save(sk_stream);
		sk_stream.close();
		// evaluation
		file_name = "./keys/evaluation-" + std::to_string(i);
		std::ofstream ek_stream(file_name, std::ios::out | std::ios::trunc | std::ios::binary);
		ev_keys[i].save(ek_stream);
		ek_stream.close();
	}
}

void initialize_() {
	PublicKey public_key[5]; //TODO: da rispostare in un modo o nell'altro come globale
	RelinKeys ev_keys[5];

	// PARAMETERS
	q_array = CoeffModulus::BFVDefault(poly_modulus_degree); // 128 is implicit

	for (int i=0; i<5; i++) {
		parms[i] = new EncryptionParameters(scheme_type::bfv);
	}

	// --t
	parms[0]->set_plain_modulus(40961);
	parms[1]->set_plain_modulus(65537);
	parms[2]->set_plain_modulus(114689);
	parms[3]->set_plain_modulus(147457);
	parms[4]->set_plain_modulus(188417);

	std::string file_name = ".";
	plain_poly_size = 4096;
	for (int i=0; i<5; i++) {
		// --n
		parms[i]->set_poly_modulus_degree(poly_modulus_degree);
		// --q
		parms[i]->set_coeff_modulus(q_array);

		context[i] = new SEALContext(*parms[i]);

		std::filesystem::path cwd = std::filesystem::current_path();
		std::cout << cwd.string();
		// LOAD KEYS
		// --public
		file_name = "./keys/public-" + std::to_string(i);
		std::ifstream pk_stream(file_name, std::ios::in | std::ios::binary);
		if (pk_stream) {
			public_key[i].load(*context[i], pk_stream);
		} else {
			std::cout << "Keys not found" << std::endl;
			std::cout << "Keys not found" << std::endl;
			throw;
		}
		pk_stream.close();
		// --secret
		file_name = "./keys/secret-" + std::to_string(i);
		std::ifstream sk_stream(file_name, std::ios::out | std::ios::binary);
		if (sk_stream) {
			secret_key[i].load(*context[i], sk_stream);
		} else {
			std::cout << "Keys not found" << std::endl;
			std::cout << "Keys not found" << std::endl;
			throw;
		}
		sk_stream.close();
		// --evaluation
		file_name = "./keys/evaluation-" + std::to_string(i);
		std::ifstream ek_stream(file_name, std::ios::out | std::ios::binary);
		if (ek_stream) {
			ev_keys[i].load(*context[i], ek_stream);
		} else {
			std::cout << "Keys not found" << std::endl;
			std::cout << "Keys not found" << std::endl;
			throw;
		}
		ek_stream.close();
		
		// OBJECTS
		encryptor[i] = new Encryptor(*context[i], public_key[i]);
		evaluator[i] = new Evaluator(*context[i]);
		decryptor[i] = new Decryptor(*context[i], secret_key[i]);
		crtbuilder[i] = new BatchEncoder(*context[i]);
	}

	// compute sizes of polynomials
	plain_poly_size = crtbuilder[0]->slot_count();
	enc_poly_size = 2 * q_array.size() * (plain_poly_size + 1);
}

void encrypt_tensor_(uint64_t *array_input, uint64_t *array_output, int input_axis0_size, int data_size) {
	int poly_groups_count = input_axis0_size / plain_poly_size;
	int last_group_size = input_axis0_size % plain_poly_size;
	int input_index = 0;
	int output_index = 0;
	vector<uint64_t> plain_vector(plain_poly_size, 0);

	for (int poly_group_index=0; poly_group_index<poly_groups_count; poly_group_index++) {
		input_index = poly_group_index * plain_poly_size * data_size * 5;
		output_index = poly_group_index * enc_poly_size * data_size * 5;
		for (int data_index=0; data_index<data_size; data_index++) {
			for (int t_index=0; t_index<5; t_index++) {
				for (int plain_index=0; plain_index<plain_poly_size; plain_index++) {
					plain_vector[plain_index] = array_input[input_index+(plain_index*data_size*5)];
				}
				Plaintext plain_poly;
				crtbuilder[t_index]->encode(plain_vector, plain_poly);
				Ciphertext encrypted_poly;
				encryptor[t_index]->encrypt(plain_poly, encrypted_poly);
				const uint64_t *encrypted_array = encrypted_poly.data();
				for (int enc_index=0; enc_index<enc_poly_size; enc_index++) {
					array_output[output_index+(enc_index*data_size*5)] = encrypted_array[enc_index];
				}
				input_index++;
				output_index++;
			}
		}
	}

	if (last_group_size!=0) {
		input_index = poly_groups_count * plain_poly_size * data_size * 5;
		output_index = poly_groups_count * enc_poly_size * data_size * 5;
		for (int data_index=0; data_index<data_size; data_index++) {
			for (int t_index=0; t_index<5; t_index++) {
				for (int plain_index=0; plain_index<last_group_size; plain_index++) {
					plain_vector[plain_index] = array_input[input_index+(plain_index*data_size*5)];
				}
				for (int plain_index=last_group_size; plain_index<plain_poly_size; plain_index++) {
					plain_vector[plain_index] = 0;
				}
				Plaintext plain_poly;
				crtbuilder[t_index]->encode(plain_vector, plain_poly);
				Ciphertext encrypted_poly;
				encryptor[t_index]->encrypt(plain_poly, encrypted_poly);
				const uint64_t *encrypted_array = encrypted_poly.data();
				for (int enc_index=0; enc_index<enc_poly_size; enc_index++) {
					array_output[output_index+(enc_index*data_size*5)] = encrypted_array[enc_index];
				}
				input_index++;
				output_index++;
			}
		}
	}
}

void decrypt_tensor_(uint64_t *array_input, uint64_t *array_output, int output_axis0_size, int data_size) {
	int poly_groups_count = output_axis0_size / plain_poly_size;
	int last_group_size = output_axis0_size % plain_poly_size;
	int input_index = 0;
	int output_index = 0;
	uint64_t enc_vector[enc_poly_size];

	for (int poly_group_index=0; poly_group_index<poly_groups_count; poly_group_index++) {
		output_index = poly_group_index * plain_poly_size * data_size * 5;
		input_index = poly_group_index * enc_poly_size * data_size * 5;
		for (int data_index=0; data_index<data_size; data_index++) {
			for (int t_index=0; t_index<5; t_index++) {
				for (int enc_index=0; enc_index<enc_poly_size; enc_index++) {
					enc_vector[enc_index] = array_input[input_index+(enc_index*data_size*5)];
				}
				Ciphertext encrypted_poly(*parms[t_index]); //,2 , enc_vector); //TODO: verificare se giusto (sembra che il primo parametro sia di default nel costruttore, il secondo creato internamente poi)
				Plaintext plain_poly;
				decryptor[t_index]->decrypt(encrypted_poly, plain_poly);
				vector<uint64_t> plain_vector_output;
				crtbuilder[t_index]->decode(plain_poly, plain_vector_output);
				for (int plain_index=0; plain_index<plain_poly_size; plain_index++) {
					array_output[output_index+(plain_index*data_size*5)] = plain_vector_output[plain_index];
				}                
				input_index++;
				output_index++;
			}
		}
	}

	if (last_group_size!=0) {
		output_index = poly_groups_count * plain_poly_size * data_size * 5;
		input_index = poly_groups_count * enc_poly_size * data_size * 5;
		for (int data_index=0; data_index<data_size; data_index++) {
			for (int t_index=0; t_index<5; t_index++) {
				for (int enc_index=0; enc_index<enc_poly_size; enc_index++) {
					enc_vector[enc_index] = array_input[input_index+(enc_index*data_size*5)];
				}
				Ciphertext encrypted_poly(*parms[t_index]); //,2 , enc_vector); //TODO: verificare se giusto (sembra che il primo parametro sia di default nel costruttore, il secondo creato internamente poi)
				Plaintext plain_poly;
				decryptor[t_index]->decrypt(encrypted_poly, plain_poly);
				vector<uint64_t> plain_vector_output;
				crtbuilder[t_index]->decode(plain_poly, plain_vector_output);
				for (int plain_index=0; plain_index<last_group_size; plain_index++) {
					array_output[output_index+(plain_index*data_size*5)] = plain_vector_output[plain_index];
				}                
				input_index++;
				output_index++;
			}
		}
	}
}

void square_tensor_(uint64_t *array_input, uint64_t *array_output, int input_axis0_size, int data_size) {
	RelinKeys ev_keys[5]; //TODO: da rispostare in un modo o nell'altro come globale
	

	int poly_groups_count = input_axis0_size / enc_poly_size;
	int input_index = 0;
	int output_index = 0;
	uint64_t enc_vector[enc_poly_size];

	for (int poly_group_index=0; poly_group_index<poly_groups_count; poly_group_index++) {
		input_index = poly_group_index * enc_poly_size * data_size * 5;
		output_index = poly_group_index * enc_poly_size * data_size * 5;
		for (int data_index=0; data_index<data_size; data_index++) {
			for (int t_index=0; t_index<5; t_index++) {
				for (int enc_index=0; enc_index<enc_poly_size; enc_index++) {
					enc_vector[enc_index] = array_input[input_index+(enc_index*data_size*5)];
				}

				Ciphertext encrypted_poly(*parms[t_index]); //, 2, enc_vector);  //,2 , enc_vector); //TODO: verificare se giusto (sembra che il primo parametro sia di default nel costruttore, il secondo creato internamente poi)
				// encrypted_poly.unalias(); //TODO: forse non necessario˜
				evaluator[t_index]->square_inplace(encrypted_poly);
				evaluator[t_index]->relinearize_inplace(encrypted_poly, ev_keys[t_index]);
				const uint64_t *encrypted_array = encrypted_poly.data();
				for (int enc_index=0; enc_index<enc_poly_size; enc_index++) {
					array_output[output_index+(enc_index*data_size*5)] = encrypted_array[enc_index];
				}                
				input_index++;
				output_index++;
			}
		}
	}
}

int main() {
	// generate_new_keys_();
	initialize_();
	return 0;
}