import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

KEY_DIR = "client-keys"

def ensure_dir():
    os.makedirs(KEY_DIR, exist_ok=True)

def priv_path(u): return os.path.join(KEY_DIR, f"{u}_priv.pem")
def pub_path(u):  return os.path.join(KEY_DIR, f"{u}_pub.pem")

def has_keys(u) -> bool:
    return os.path.exists(priv_path(u)) and os.path.exists(pub_path(u))

def generate_keys(u, algo):
    ensure_dir()
    if has_keys(u):
        print(f"[OK] Key sudah ada untuk '{u}'")
        return

    if algo == "ec":
        priv = ec.generate_private_key(ec.SECP256K1())
        pub = priv.public_key()
        print("[OK] Generate EC secp256k1")
    elif algo == "ed25519":
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key()
        print("[OK] Generate Ed25519")
    else:
        print("[ERR] algo harus: ec / ed25519")
        return

    with open(priv_path(u), "wb") as f:
        f.write(priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(pub_path(u), "wb") as f:
        f.write(pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(" private:", priv_path(u))
    print(" public :", pub_path(u))

def load_priv(u):
    if not os.path.exists(priv_path(u)):
        raise FileNotFoundError(f"Private key belum ada: {priv_path(u)}. Generate dulu.")
    with open(priv_path(u), "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def sign_hex(priv, message: str) -> str:
    m = message.encode("utf-8")
    if isinstance(priv, ec.EllipticCurvePrivateKey):
        sig = priv.sign(m, ec.ECDSA(hashes.SHA256()))
    else:
        sig = priv.sign(m)
    return sig.hex()

def menu_panduan(u: str):
    while True:
        print("\nMenu Panduan:")
        print("3) Panduan /store (upload pubkey)")
        print("4) Buat signature_hex untuk /login (LOGIN_ACTION)")
        print("5) Buat signature_hex untuk /verify (isi pesan bebas)")
        print("0) Keluar")
        c = input("Pilih: ").strip()

        if c == "3":
            print("\n=== store ===")
            print("username:", u)
            print("upload file:", pub_path(u))
            print("Lalu Execute.\n")

        elif c == "4":
            priv = load_priv(u)
            msg = "LOGIN_ACTION"
            print("\n=== /login ===")
            print("username:", u)
            print("signature_hex:", sign_hex(priv, msg))
            print("pesan yang ditandatangani:", msg)
            print()

        elif c == "5":
            priv = load_priv(u)
            msg = input("pesan: ").strip()
            if not msg:
                print("[ERR] pesan kosong")
                continue
            print("\n=== /verify ===")
            print("username:", u)
            print("pesan:", msg)
            print("signature_hex:", sign_hex(priv, msg))
            print()

        elif c == "0":
            break
        else:
            print("[ERR] pilihan tidak valid")

if __name__ == "__main__":
    u = input("Username: ").strip()
    if not u:
        print("[ERR] username kosong")
        raise SystemExit

    # Kalau key belum ada, minta pilih generate dulu (hanya 2 pilihan)
    if not has_keys(u):
        print("\nKey belum ada. Pilih algoritma untuk generate:")
        print("1) Generate key EC")
        print("2) Generate key Ed25519")
        g = input("Pilih (1/2): ").strip()

        if g == "1":
            generate_keys(u, "ec")
        elif g == "2":
            generate_keys(u, "ed25519")
        else:
            print("[ERR] pilihan tidak valid")
            raise SystemExit

    # Kalau key sudah ada, masuk panduan 3-5
    print(f"\n Key untuk '{u}' tersedia.")
    menu_panduan(u)
