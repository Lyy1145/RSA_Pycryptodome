import re
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os

class RSATool:
    def __init__(self, root):
        self.root = root
        self.password_pattern = re.compile(r'^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$')
        self.setup_ui()
        self.rsaf_dir = ".\\RSAF"  # 定义存储加密文件块的目录，使用相对路径

    def setup_ui(self):
        self.root.title("RSA 加密/解密工具")

        # 添加服务选择标签和下拉框
        service_label = tk.Label(self.root, text="服务选择：(1加密/2解密/3生成密钥对)")
        service_label.grid(row=0, column=0, pady=5)

        self.service_var = tk.StringVar(self.root)
        service_options = ['1加密', '2解密', '3生成密钥对']
        self.service_combobox = ttk.Combobox(self.root, textvariable=self.service_var, values=service_options)
        self.service_combobox.grid(row=0, column=1, pady=5)
        self.service_combobox.bind('<<ComboboxSelected>>', self.update_file_path_entry_state)

        # 添加输入框和标签
        password_label = tk.Label(self.root, text="密钥对密码（格式：YVC9B-7FSH6-UYK91）：")
        password_label.grid(row=1, column=0)
        self.e2 = tk.Entry(self.root)
        self.e2.grid(row=1, column=1)

        file_label = tk.Label(self.root, text="文件路径：")
        file_label.grid(row=2, column=0)
        self.e3 = tk.Entry(self.root)
        self.e3.grid(row=2, column=1)

        # 添加按钮
        execute_button = tk.Button(self.root, text="执行", command=self.main)
        execute_button.grid(row=3, column=0, columnspan=2, pady=5)

    def update_file_path_entry_state(self, event):
        service = self.service_combobox.get()
        if service == '3生成密钥对':
            self.e3.configure(state='disabled')
        else:
            self.e3.configure(state='normal')

    def generate_key_pairs(self, secret_code):
        try:
            private_keys = []
            public_keys = []
            for i in range(1, 4):  # Generate three key pairs
                key = RSA.generate(2048)
                private_key_export = key.export_key(passphrase=secret_code, pkcs=8,
                                                     protection="scryptAndAES128-CBC",
                                                     prot_params={'iteration_count': 131072})
                public_key_export = key.publickey().export_key()
                with open(f'private_key_F{i}.rask', 'wb') as f:
                    f.write(private_key_export)
                with open(f'public_key_F{i}.rask', 'wb') as f:
                    f.write(public_key_export)
                private_keys.append(key)
                public_keys.append(key.publickey())
            messagebox.showinfo("成功", "密钥对生成成功。")
            return private_keys, public_keys
        except Exception as e:
            messagebox.showerror("错误", f"生成密钥对过程中发生错误：{e}")
            self.delete_key_files()
            return None, None

    def load_key_pairs(self, secret_code):
        try:
            private_keys = []
            public_keys = []
            for i in range(1, 4):  # Load three key pairs
                with open(f'private_key_F{i}.rask', 'rb') as f:
                    private_key = RSA.import_key(f.read(), passphrase=secret_code)
                with open(f'public_key_F{i}.rask', 'rb') as f:
                    public_key = RSA.import_key(f.read())
                private_keys.append(private_key)
                public_keys.append(public_key)
            return private_keys, public_keys
        except Exception as e:
            messagebox.showerror("错误", f"加载密钥对过程中发生错误：{e}")
            self.delete_key_files()
            return None, None

    def delete_key_files(self):
        for i in range(1, 4):
            try:
                os.remove(f'private_key_F{i}.rask')
                os.remove(f'public_key_F{i}.rask')
            except FileNotFoundError:
                pass

    def main(self):
        service = self.service_var.get()
        password = self.e2.get()
        if not self.password_pattern.match(password):
            messagebox.showwarning("警告", "密码格式不正确，应为大写字母和数字组合，用'-'分隔成三部分，每部分5个字符。")
            return
        
        passwords = password.split('-')
        
        if len(passwords) != 3:
            messagebox.showwarning("警告", "密码格式不正确，应为三级密码，用'-'分隔。")
            return
        
        try:
            if service == '1加密':
                file_path = self.e3.get()
                private_keys, public_keys = self.load_key_pairs(passwords[0])
                if public_keys is None or private_keys is None:
                    return
                self.encrypt_file(file_path, public_keys)
            elif service == '2解密':
                file_path = self.e3.get()
                private_keys, public_keys = self.load_key_pairs(passwords[0])
                if private_keys is None or public_keys is None:
                    return
                self.decrypt_file(file_path, private_keys)
            elif service == '3生成密钥对':
                self.generate_key_pairs(passwords[0])
            else:
                messagebox.showwarning("警告", "无效的服务选择。")
        except Exception as e:
            messagebox.showerror("错误", f"执行操作过程中发生错误：{e}")
            self.delete_key_files()

    def ensure_rsaf_dir(self):
        if not os.path.exists(self.rsaf_dir):
            os.makedirs(self.rsaf_dir)

    def encrypt_file(self, file_path, public_keys):
        try:
            self.ensure_rsaf_dir()  # 确保RSAF目录存在
            with open(file_path, 'rb') as file:
                chunk_index = 0
                while True:
                    chunk = file.read(190)  # 使用190字节的块大小
                    if not chunk:
                        break
                    encrypted_chunk = b''
                    for public_key in public_keys:
                        cipher = PKCS1_OAEP.new(public_key)
                        encrypted_chunk += cipher.encrypt(chunk)
                    file_block_path = os.path.join(self.rsaf_dir, f"{os.path.basename(file_path)}_block_{chunk_index}.enc")
                    with open(file_block_path, 'wb') as enc_file:
                        enc_file.write(encrypted_chunk)
                    chunk_index += 1
            messagebox.showinfo("成功", "文件加密成功，文件块存储在RSAF目录下。")
            os.remove(file_path)  # 删除原始文件
        except Exception as e:
            messagebox.showerror("错误", f"加密文件过程中发生错误：{e}")
            self.delete_key_files()

    def decrypt_file(self, file_path, private_keys):
        try:
            self.ensure_rsaf_dir()  # 确保RSAF目录存在
            file_blocks = [f for f in os.listdir(self.rsaf_dir) if f.startswith(os.path.basename(file_path))]
            decrypted_data = b''
            for file_block in sorted(file_blocks):  # 确保文件块的顺序
                file_block_path = os.path.join(self.rsaf_dir, file_block)
                with open(file_block_path, 'rb') as enc_file:
                    encrypted_chunk = enc_file.read()
                for private_key in reversed(private_keys):  # Decrypt in reverse order
                    cipher = PKCS1_OAEP.new(private_key)
                    try:
                        decrypted_chunk = cipher.decrypt(encrypted_chunk)
                        decrypted_data += decrypted_chunk
                        break  # Assuming the first successful decryption is the correct one
                    except (ValueError, IndexError):
                        # If decryption fails, try the next private key
                        continue
            # 写入解密后的数据到原文件
            with open(file_path, 'wb') as file:
                file.write(decrypted_data)
            if decrypted_data:
                messagebox.showinfo("成功", "文件解密成功，原文件已被覆盖。")
            else:
                messagebox.showerror("错误", "所有密钥解密失败，文件内容丢失。")
        except Exception as e:
            messagebox.showerror("错误", f"解密文件过程中发生错误：{e}")
            self.delete_key_files()

    def _chunk_data(self, data, chunk_size):
        """Yield successive n-sized chunks from data."""
        for i in range(0, len(data), chunk_size):
            yield data[i:i + chunk_size]

if __name__ == "__main__":
    root = tk.Tk()
    app = RSATool(root)
    root.mainloop()