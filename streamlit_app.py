import streamlit as st
import os

# --- Alberti Cipher Functions ---

# Define the 25-character alphabet for Alberti cipher (J is treated as I)
# Definir el alfabeto de 25 caracteres para el cifrado de Alberti (J se trata como I)
ALPHABET = "ABCDEFGHIKLMNOPQRSTVWXYZ" # 25 characters, J excluded

def create_alberti_discs(initial_offset):
    """
    Creates the outer and inner Alberti cipher discs.
    The inner disc is a cyclic shift of the outer disc based on initial_offset.
    Crea los discos exterior e interior del cifrado de Alberti.
    El disco interior es un desplazamiento cíclico del disco exterior basado en el desplazamiento_inicial.
    """
    outer_ring = ALPHABET
    # Ensure offset is within the alphabet range
    offset = initial_offset % len(ALPHABET)
    inner_ring = ALPHABET[offset:] + ALPHABET[:offset]
    return outer_ring, inner_ring

def cifrar_alberti(message, initial_offset, shift_interval):
    """
    Encrypts a message using the Alberti cipher.
    Cifra un mensaje usando el cifrado de Alberti.
    """
    # Normalize message: uppercase, replace J with I, remove non-alphabetic
    # Normalizar mensaje: mayúsculas, reemplazar J por I, eliminar no alfabéticos
    processed_message = "".join(char for char in message.upper() if char.isalpha()).replace("J", "I")

    outer_ring, current_inner_ring = create_alberti_discs(initial_offset)
    ciphertext = []
    char_count = 0

    for char in processed_message:
        if char in outer_ring:
            fixed_idx = outer_ring.find(char)
            cipher_char = current_inner_ring[fixed_idx]
            ciphertext.append(cipher_char)
            char_count += 1

            # Rotate inner ring after 'shift_interval' characters
            # Rotar el disco interior después de 'shift_interval' caracteres
            if shift_interval > 0 and char_count % shift_interval == 0:
                current_inner_ring = current_inner_ring[1:] + current_inner_ring[0]
        else:
            # Keep non-alphabetic characters as they are (e.g., spaces, numbers, punctuation)
            # Mantener los caracteres no alfabéticos tal cual (ej. espacios, números, puntuación)
            ciphertext.append(char) # This will append original non-alpha chars, not processed_message ones
            
    # Reconstruct the message with original spacing/non-alpha characters for better readability
    # Reconstruir el mensaje con el espaciado/caracteres no alfabéticos originales para mejor legibilidad
    original_message_chars = list(message.upper())
    encrypted_index = 0
    final_ciphertext_with_formatting = []
    for original_char in original_message_chars:
        if original_char.isalpha():
            if encrypted_index < len(ciphertext):
                final_ciphertext_with_formatting.append(ciphertext[encrypted_index])
                encrypted_index += 1
            else:
                final_ciphertext_with_formatting.append(original_char) # Should not happen if logic is correct
        else:
            final_ciphertext_with_formatting.append(original_char)

    return "".join(final_ciphertext_with_formatting)


def descifrar_alberti(ciphertext, initial_offset, shift_interval):
    """
    Decrypts a message encrypted with the Alberti cipher.
    Descifra un mensaje cifrado con el cifrado de Alberti.
    """
    # Normalize ciphertext: uppercase, replace J with I, remove non-alphabetic
    # Normalizar texto cifrado: mayúsculas, reemplazar J por I, eliminar no alfabéticos
    processed_ciphertext = "".join(char for char in ciphertext.upper() if char.isalpha()).replace("J", "I")

    outer_ring, current_inner_ring = create_alberti_discs(initial_offset)
    plaintext = []
    char_count = 0

    for char in processed_ciphertext:
        if char in outer_ring:
            inner_idx = current_inner_ring.find(char)
            if inner_idx == -1: # Character not found in current inner ring (should not happen for valid ciphertexts)
                plaintext.append(char) # Append as is if not found
                continue

            plain_char = outer_ring[inner_idx]
            plaintext.append(plain_char)
            char_count += 1

            # Rotate inner ring after 'shift_interval' characters (same as encryption)
            # Rotar el disco interior después de 'shift_interval' caracteres (igual que el cifrado)
            if shift_interval > 0 and char_count % shift_interval == 0:
                current_inner_ring = current_inner_ring[1:] + current_inner_ring[0]
        else:
            # Keep non-alphabetic characters as they are
            # Mantener los caracteres no alfabéticos tal cual
            plaintext.append(char)

    # Reconstruct the message with original spacing/non-alpha characters for better readability
    # This part is tricky for decryption if original non-alpha chars are not preserved in ciphertext
    # For simplicity, we'll just return the processed plaintext.
    return "".join(plaintext)

# --- Streamlit User Interface ---

st.set_page_config(page_title="Cifrador de Alberti", layout="centered")

st.title("🔐 Cifrador de Alberti")
st.subheader("(Disco móvil giratorio)")
st.markdown("---")
st.write("Script desarrollado por **Marcos Sebastian Cunioli** - Especialista en Ciberseguridad")
st.markdown("---")

# Display Alberti Discs
st.subheader("Configuración de Discos de Alberti")
initial_offset = st.slider(
    "Desplazamiento inicial del disco interior (0-24):",
    min_value=0,
    max_value=len(ALPHABET) - 1,
    value=0,
    step=1,
    key="initial_offset"
)

shift_interval = st.number_input(
    "Intervalo de rotación del disco interior (cada cuántos caracteres gira 1 posición):",
    min_value=1,
    value=5,
    step=1,
    key="shift_interval"
)

outer_ring_display, inner_ring_display = create_alberti_discs(initial_offset)

st.write(f"**Disco Exterior (Fijo):** `{outer_ring_display}`")
st.write(f"**Disco Interior (Móvil, inicial):** `{inner_ring_display}`")
st.markdown("---")

# Encryption Section
st.header("Cifrar Mensaje")
message_to_encrypt = st.text_area("Ingrese el mensaje a cifrar:", height=100, key="encrypt_message")

if st.button("Cifrar Mensaje", key="btn_encrypt"):
    if message_to_encrypt:
        try:
            encrypted_text = cifrar_alberti(message_to_encrypt, initial_offset, shift_interval)
            st.success(f"**Texto cifrado:** `{encrypted_text}`")
            st.download_button(
                label="Descargar Texto Cifrado",
                data=encrypted_text,
                file_name="mensaje_cifrado_alberti.txt",
                mime="text/plain"
            )
        except Exception as e:
            st.error(f"Error al cifrar: {e}")
    else:
        st.warning("Por favor, ingrese un mensaje para cifrar.")

st.markdown("---")

# Decryption Section
st.header("Descifrar Mensaje")

decryption_option = st.radio(
    "¿Cómo desea descifrar el mensaje?",
    ("Ingresar texto cifrado directamente", "Cargar desde un archivo"),
    key="decryption_option"
)

# Important: Decryption needs the same initial_offset and shift_interval
# Importante: El descifrado necesita el mismo desplazamiento_inicial y el mismo intervalo_de_rotación
st.info("Para descifrar, asegúrese de usar el mismo 'Desplazamiento inicial' y 'Intervalo de rotación' que se usaron para cifrar.")


if decryption_option == "Ingresar texto cifrado directamente":
    ciphertext_input = st.text_area("Ingrese el texto cifrado:", height=100, key="decrypt_input")
    
    if st.button("Descifrar Texto", key="btn_decrypt_input"):
        if ciphertext_input:
            try:
                decrypted_text = descifrar_alberti(ciphertext_input, initial_offset, shift_interval)
                st.info(f"**Texto descifrado:** `{decrypted_text}`")
            except Exception as e:
                st.error(f"Error al descifrar: {e}")
        else:
            st.warning("Por favor, ingrese el texto cifrado para descifrar.")

elif decryption_option == "Cargar desde un archivo":
    uploaded_file = st.file_uploader("Cargue un archivo de texto (.txt) con el mensaje cifrado:", type="txt", key="file_uploader")
    
    if st.button("Descifrar Archivo", key="btn_decrypt_file"):
        if uploaded_file is not None:
            content_from_file = uploaded_file.read().decode("utf-8").strip()
            if content_from_file:
                try:
                    decrypted_text = descifrar_alberti(content_from_file, initial_offset, shift_interval)
                    st.info(f"**Texto descifrado desde archivo:** `{decrypted_text}`")
                except Exception as e:
                    st.error(f"Error al descifrar: {e}")
            else:
                st.error("El archivo cargado está vacío o no se pudo leer.")
        else:
            st.warning("Por favor, cargue un archivo para descifrar.")

st.markdown("---")
st.markdown("Una herramienta de criptografía clásica para fines educativos y demostrativos.")
