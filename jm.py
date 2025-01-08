import re
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import zipfile
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad


class RSAEncryptionTool:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA 四级加密/解密工具")
        self.single_password_pattern = re.compile(r'^[A-Z0-9]{5}$')  # 单个密码：5位数字或大写字母
        self.combined_password_pattern = re.compile(r'^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$')  # 组合密码：三段5位数字或大写字母
        self.rsaf_dir = ".\\RSAF"
        self.temp_dir = ".\\TEMP"
        self.rsa_key_size = 4096
        self.setup_ui()

    def setup_ui(self):
        # 创建主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # 操作选择
        ttk.Label(main_frame, text="选择操作:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.operation = ttk.Combobox(main_frame, values=['加密文件', '解密文件', '生成密钥对'])
        self.operation.grid(row=0, column=1, sticky=tk.W, pady=5)
        self.operation.set('加密文件')
        self.operation.bind('<<ComboboxSelected>>', self.on_operation_change)

        # 密码输入
        ttk.Label(main_frame, text="密钥密码 (每段5位数字或大写字母):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.password_entry = ttk.Entry(main_frame, width=30)
        self.password_entry.grid(row=1, column=1, sticky=tk.W, pady=5)

        # 文件选择
        ttk.Label(main_frame, text="选择文件:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.file_frame = ttk.Frame(main_frame)
        self.file_frame.grid(row=2, column=1, sticky=tk.W, pady=5)
        
        self.file_entry = ttk.Entry(self.file_frame, width=30)
        self.file_entry.grid(row=0, column=0, padx=(0, 5))
        
        self.browse_button = ttk.Button(self.file_frame, text="浏览", command=self.browse_file)
        self.browse_button.grid(row=0, column=1)

        # 解密文件路径选择（新增）
        self.decrypt_path_frame = ttk.Frame(main_frame)
        self.decrypt_path_frame.grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=5)
        ttk.Label(self.decrypt_path_frame, text="解密文件路径:").grid(row=0, column=0, sticky=tk.W)
        self.decrypt_path_entry = ttk.Entry(self.decrypt_path_frame, width=30)
        self.decrypt_path_entry.grid(row=0, column=1, padx=5)
        self.decrypt_browse_button = ttk.Button(self.decrypt_path_frame, text="浏览", command=self.browse_decrypt_path)
        self.decrypt_browse_button.grid(row=0, column=2)
        
        # 初始化时隐藏解密路径框
        self.decrypt_path_frame.grid_remove()

        # 执行按钮移到最后
        self.execute_button = ttk.Button(main_frame, text="执行", command=self.execute_operation)
        self.execute_button.grid(row=4, column=0, columnspan=2, pady=10)

    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, filename)

    def browse_decrypt_path(self):
        path = filedialog.askdirectory()
        if path:
            self.decrypt_path_entry.delete(0, tk.END)
            self.decrypt_path_entry.insert(0, path)

    def on_operation_change(self, event=None):
        if self.operation.get() == '生成密钥对':
            self.file_entry.configure(state='disabled')
            self.browse_button.configure(state='disabled')
            self.decrypt_path_frame.grid_remove()
        elif self.operation.get() == '解密文件':
            self.file_entry.configure(state='normal')
            self.browse_button.configure(state='normal')
            self.decrypt_path_frame.grid()
        else:  # 加密文件
            self.file_entry.configure(state='normal')
            self.browse_button.configure(state='normal')
            self.decrypt_path_frame.grid_remove()

    def execute_operation(self):
        operation = self.operation.get()
        password = self.password_entry.get()
        
        # 根据操作类型检查密码格式
        if operation == '生成密钥对':
            if not self.combined_password_pattern.match(password):
                messagebox.showerror("错误", "密码格式错误！\n每段必须是5位数字或大写字母，格式: XXXXX-XXXXX-XXXXX\n例如：12345-ABCDE-1A2B3")
                return
        else:
            if not self.combined_password_pattern.match(password):
                messagebox.showerror("错误", "密码格式错误！\n每段必须是5位数字或大写字母，格式: XXXXX-XXXXX-XXXXX\n例如：12345-ABCDE-1A2B3")
                return

        try:
            if operation == '生成密钥对':
                self.generate_key_pairs(password)
            else:
                filepath = self.file_entry.get()
                if not filepath:
                    messagebox.showerror("错误", "请选择文件！")
                    return
                if not os.path.exists(filepath):
                    messagebox.showerror("错误", "文件不存在！")
                    return
                
                if operation == '加密文件':
                    self.encrypt_file(filepath, password)
                else:  # 解密文件
                    self.decrypt_file(filepath, password)
        except Exception as e:
            messagebox.showerror("错误", f"操作失败: {str(e)}")
            self.cleanup_keys()

    def generate_key_pairs(self, password):
        try:
            # 分割前三级密码
            passwords = password.split('-')
            
            # 生成前三级密钥对，使用分割后的密码
            for i, pwd in enumerate(passwords):
                key = RSA.generate(self.rsa_key_size)
                private_key = key.export_key(passphrase=pwd,
                                          pkcs=8,
                                          protection="scryptAndAES128-CBC")
                public_key = key.publickey().export_key()
                
                with open(f'private_key_{i+1}.pem', 'wb') as f:
                    f.write(private_key)
                with open(f'public_key_{i+1}.pem', 'wb') as f:
                    f.write(public_key)
            
            # 生成第四级密钥对，使用完整密码字符串
            key4 = RSA.generate(self.rsa_key_size)
            private_key4 = key4.export_key(passphrase=password,  # 使用完整密码
                                         pkcs=8,
                                         protection="scryptAndAES128-CBC")
            public_key4 = key4.publickey().export_key()
            
            with open('private_key_4.pem', 'wb') as f:
                f.write(private_key4)
            with open('public_key_4.pem', 'wb') as f:
                f.write(public_key4)
            
            messagebox.showinfo("成功", "四对密钥生成完成！")
        except Exception as e:
            self.cleanup_keys()
            raise Exception(f"生成密钥对失败: {str(e)}")

    def encrypt_file(self, filepath, password):
        if not os.path.exists(self.temp_dir):
            os.makedirs(self.temp_dir)

        try:
            # 保存原文件名和扩展名
            filename = os.path.basename(filepath)
            filename_file = os.path.join(self.temp_dir, "filename.txt")
            with open(filename_file, 'w', encoding='utf-8') as f:
                f.write(filename)

            # 加载四个公钥
            public_keys = []
            for i in range(1, 5):
                with open(f'public_key_{i}.pem', 'rb') as f:
                    public_keys.append(RSA.import_key(f.read()))

            # 分别加密文件名和原文件
            file_pairs = [
                (filename_file, "filename"),
                (filepath, "content")
            ]

            encrypted_files = []
            for src_file, prefix in file_pairs:
                # 第一级加密：分块RSA加密
                block_size = 256
                first_stage_files = []
                with open(src_file, 'rb') as f:
                    block_num = 0
                    while True:
                        data = f.read(block_size)
                        if not data:
                            break
                        
                        cipher_rsa = PKCS1_OAEP.new(public_keys[0])
                        encrypted_data = cipher_rsa.encrypt(data)
                        
                        block_file = os.path.join(self.temp_dir, f"{prefix}_block_{block_num}.enc")
                        with open(block_file, 'wb') as bf:
                            bf.write(encrypted_data)
                        first_stage_files.append(block_file)
                        block_num += 1

                # 压缩第一级加密结果
                first_zip = os.path.join(self.temp_dir, f"{prefix}_stage1.zip")
                with zipfile.ZipFile(first_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
                    for file in first_stage_files:
                        zf.write(file, os.path.basename(file))
                        os.remove(file)
                encrypted_files.append(first_zip)

            # 合并两个加密文件到一个压缩包
            combined_zip = os.path.join(self.temp_dir, "combined.zip")
            with zipfile.ZipFile(combined_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
                for file in encrypted_files:
                    zf.write(file, os.path.basename(file))
                    os.remove(file)

            # 第二级加密
            with open(combined_zip, 'rb') as f:
                data = f.read()
            os.remove(combined_zip)
            
            second_stage_files = []
            for i in range(0, len(data), block_size):
                chunk = data[i:i + block_size]
                if len(chunk) < block_size:
                    chunk = pad(chunk, block_size)
                cipher_rsa = PKCS1_OAEP.new(public_keys[1])
                encrypted_chunk = cipher_rsa.encrypt(chunk)
                
                chunk_file = os.path.join(self.temp_dir, f"stage2_chunk_{i//block_size}.enc")
                with open(chunk_file, 'wb') as f:
                    f.write(encrypted_chunk)
                second_stage_files.append(chunk_file)

            # 第二级压缩
            second_zip = os.path.join(self.temp_dir, "stage2.zip")
            with zipfile.ZipFile(second_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
                for file in second_stage_files:
                    zf.write(file, os.path.basename(file))
                    os.remove(file)

            # 第三级加密
            with open(second_zip, 'rb') as f:
                data = f.read()
            os.remove(second_zip)
            
            third_stage_files = []
            for i in range(0, len(data), block_size):
                chunk = data[i:i + block_size]
                if len(chunk) < block_size:
                    chunk = pad(chunk, block_size)
                cipher_rsa = PKCS1_OAEP.new(public_keys[2])
                encrypted_chunk = cipher_rsa.encrypt(chunk)
                
                chunk_file = os.path.join(self.temp_dir, f"stage3_chunk_{i//block_size}.enc")
                with open(chunk_file, 'wb') as f:
                    f.write(encrypted_chunk)
                third_stage_files.append(chunk_file)

            # 第三级压缩
            third_zip = os.path.join(self.temp_dir, "stage3.zip")
            with zipfile.ZipFile(third_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
                for file in third_stage_files:
                    zf.write(file, os.path.basename(file))
                    os.remove(file)

            # 第四级加密
            with open(third_zip, 'rb') as f:
                data = f.read()
            os.remove(third_zip)
            
            final_stage_files = []
            for i in range(0, len(data), block_size):
                chunk = data[i:i + block_size]
                if len(chunk) < block_size:
                    chunk = pad(chunk, block_size)
                cipher_rsa = PKCS1_OAEP.new(public_keys[3])
                encrypted_chunk = cipher_rsa.encrypt(chunk)
                
                chunk_file = os.path.join(self.temp_dir, f"final_chunk_{i//block_size}.enc")
                with open(chunk_file, 'wb') as f:
                    f.write(encrypted_chunk)
                final_stage_files.append(chunk_file)

            # 最终压缩
            final_file = os.path.join('.', f"{os.path.basename(filepath)}.enc")
            with zipfile.ZipFile(final_file, 'w', zipfile.ZIP_DEFLATED) as zf:
                for file in final_stage_files:
                    zf.write(file, os.path.basename(file))
                    os.remove(file)

            os.remove(filepath)
            # 修改成功提示，显示加密文件的完整路径
            abs_path = os.path.abspath(final_file)
            messagebox.showinfo("成功", f"文件加密完成！\n加密文件保存在: {abs_path}")

        except Exception as e:
            self.cleanup_temp_files()
            raise Exception(f"加密失败: {str(e)}")

    def decrypt_file(self, filepath, password):
        if not os.path.exists(self.temp_dir):
            os.makedirs(self.temp_dir)

        try:
            decrypt_path = self.decrypt_path_entry.get()
            if not decrypt_path:
                raise Exception("请选择解密文件保存路径")

            # 检查加密文件是否存在
            if not filepath.endswith('.enc'):
                filepath = filepath + '.enc'
            
            if not os.path.exists(filepath):
                enc_filepath = os.path.join(self.rsaf_dir, os.path.basename(filepath))
                if not os.path.exists(enc_filepath):
                    raise Exception(f"找不到加密文件：{filepath} 或 {enc_filepath}")
                filepath = enc_filepath

            # 加载RSA私钥
            private_keys = []
            # 加载前三级密钥，使用分割后的密码
            passwords = password.split('-')
            for i, pwd in enumerate(passwords):
                with open(f'private_key_{i+1}.pem', 'rb') as f:
                    private_keys.append(RSA.import_key(f.read(), passphrase=pwd))
            
            # 加载第四级密钥，使用完整密码字符串
            with open('private_key_4.pem', 'rb') as f:
                private_keys.append(RSA.import_key(f.read(), passphrase=password))

            # 解压最终加密文件
            with zipfile.ZipFile(filepath, 'r') as zf:
                zf.extractall(self.temp_dir)

            # 第四级解密
            final_chunks = sorted([f for f in os.listdir(self.temp_dir) if f.startswith("final_chunk_")],
                                key=lambda x: int(x.split('_')[2].split('.')[0]))
            third_stage_data = b''
            
            for chunk_file in final_chunks:
                with open(os.path.join(self.temp_dir, chunk_file), 'rb') as f:
                    encrypted_chunk = f.read()
                cipher_rsa = PKCS1_OAEP.new(private_keys[3])
                try:
                    decrypted_chunk = cipher_rsa.decrypt(encrypted_chunk)
                    if chunk_file == final_chunks[-1]:
                        try:
                            decrypted_chunk = unpad(decrypted_chunk, 256)
                        except:
                            pass
                    third_stage_data += decrypted_chunk
                except:
                    raise Exception("第四级解密失败")

            # 保存并解压第三级数据
            third_zip = os.path.join(self.temp_dir, "stage3.zip")
            with open(third_zip, 'wb') as f:
                f.write(third_stage_data)

            # 清理第四级文件
            for f in final_chunks:
                os.remove(os.path.join(self.temp_dir, f))

            # 解压第三级数据
            with zipfile.ZipFile(third_zip, 'r') as zf:
                zf.extractall(self.temp_dir)
            os.remove(third_zip)

            # 第三级解密
            third_chunks = sorted([f for f in os.listdir(self.temp_dir) if f.startswith("stage3_chunk_")],
                                key=lambda x: int(x.split('_')[2].split('.')[0]))
            second_stage_data = b''
            
            for chunk_file in third_chunks:
                with open(os.path.join(self.temp_dir, chunk_file), 'rb') as f:
                    encrypted_chunk = f.read()
                cipher_rsa = PKCS1_OAEP.new(private_keys[2])
                try:
                    decrypted_chunk = cipher_rsa.decrypt(encrypted_chunk)
                    if chunk_file == third_chunks[-1]:
                        try:
                            decrypted_chunk = unpad(decrypted_chunk, 256)
                        except:
                            pass
                    second_stage_data += decrypted_chunk
                except:
                    raise Exception("第三级解密失败")

            # 保存并解压第二级数据
            second_zip = os.path.join(self.temp_dir, "stage2.zip")
            with open(second_zip, 'wb') as f:
                f.write(second_stage_data)

            # 清理第三级文件
            for f in third_chunks:
                os.remove(os.path.join(self.temp_dir, f))

            # 解压第二级数据
            with zipfile.ZipFile(second_zip, 'r') as zf:
                zf.extractall(self.temp_dir)
            os.remove(second_zip)

            # 第二级解密
            second_chunks = sorted([f for f in os.listdir(self.temp_dir) if f.startswith("stage2_chunk_")],
                                 key=lambda x: int(x.split('_')[2].split('.')[0]))
            first_stage_data = b''
            
            for chunk_file in second_chunks:
                with open(os.path.join(self.temp_dir, chunk_file), 'rb') as f:
                    encrypted_chunk = f.read()
                cipher_rsa = PKCS1_OAEP.new(private_keys[1])
                try:
                    decrypted_chunk = cipher_rsa.decrypt(encrypted_chunk)
                    if chunk_file == second_chunks[-1]:
                        try:
                            decrypted_chunk = unpad(decrypted_chunk, 256)
                        except:
                            pass
                    first_stage_data += decrypted_chunk
                except:
                    raise Exception("第二级解密失败")

            # 保存并解压第一级数据
            combined_zip = os.path.join(self.temp_dir, "combined.zip")
            with open(combined_zip, 'wb') as f:
                f.write(first_stage_data)

            # 清理第二级文件
            for f in second_chunks:
                os.remove(os.path.join(self.temp_dir, f))

            # 解压合并的文件
            with zipfile.ZipFile(combined_zip, 'r') as zf:
                zf.extractall(self.temp_dir)
            os.remove(combined_zip)

            # 分别解压文件名和内容的第一级加密文件
            for prefix in ["filename", "content"]:
                first_zip = os.path.join(self.temp_dir, f"{prefix}_stage1.zip")
                with zipfile.ZipFile(first_zip, 'r') as zf:
                    zf.extractall(self.temp_dir)
                os.remove(first_zip)

            # 解密文件名
            filename_blocks = sorted([f for f in os.listdir(self.temp_dir) if f.startswith("filename_block_")],
                                   key=lambda x: int(x.split('_')[2].split('.')[0]))
            filename_data = b''
            
            for block in filename_blocks:
                with open(os.path.join(self.temp_dir, block), 'rb') as f:
                    encrypted_data = f.read()
                cipher_rsa = PKCS1_OAEP.new(private_keys[0])
                try:
                    decrypted_data = cipher_rsa.decrypt(encrypted_data)
                    filename_data += decrypted_data
                except:
                    raise Exception("文件名解密失败")

            original_filename = filename_data.decode('utf-8')

            # 解密文件内容
            content_blocks = sorted([f for f in os.listdir(self.temp_dir) if f.startswith("content_block_")],
                                  key=lambda x: int(x.split('_')[2].split('.')[0]))
            
            # 构建最终输出路径
            output_file = os.path.join(decrypt_path, original_filename)
            
            with open(output_file, 'wb') as outfile:
                for block in content_blocks:
                    with open(os.path.join(self.temp_dir, block), 'rb') as f:
                        encrypted_data = f.read()
                    cipher_rsa = PKCS1_OAEP.new(private_keys[0])
                    try:
                        decrypted_data = cipher_rsa.decrypt(encrypted_data)
                        outfile.write(decrypted_data)
                    except:
                        raise Exception("文件内容解密失败")

            # 清理所有临时文件
            self.cleanup_temp_files()
            os.remove(filepath)
            messagebox.showinfo("成功", f"文件已解密到: {output_file}")

        except Exception as e:
            self.cleanup_temp_files()
            if 'output_file' in locals() and os.path.exists(output_file):
                try:
                    os.remove(output_file)
                except:
                    pass
            raise Exception(f"解密失败: {str(e)}")

    def cleanup_keys(self):
        # 清理四对密钥
        for i in range(1, 5):
            try:
                os.remove(f'private_key_{i}.pem')
                os.remove(f'public_key_{i}.pem')
            except:
                pass

    def cleanup_temp_files(self):
        if os.path.exists(self.temp_dir):
            for file in os.listdir(self.temp_dir):
                try:
                    os.remove(os.path.join(self.temp_dir, file))
                except Exception:
                    pass

if __name__ == "__main__":
    root = tk.Tk()
    app = RSAEncryptionTool(root)
    root.mainloop()
