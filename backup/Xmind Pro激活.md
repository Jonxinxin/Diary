PS：如果以前替换过公钥，需要还原一下app.asar再执行一键脚本，否则重新生成的公钥会不匹配；没备份app.asar的话建议重装最新版。

[Xmind](https://xmind.app/)是什么不用我多介绍了吧，52上已经有类似的授权分析了，只是步骤比较繁琐，还要安装nodejs解包asar文件，其实asar就是一个归档格式，python中也有类似的第三方包[asarPy](https://pypi.org/project/asarPy)，懒得下载nodejs，直接用python脚本实现一键解包替换（hook文件需提前下载，文末有完整版），直接贴码：

```
import os
import pathlib
import shutil
from abc import ABCMeta
from abc import abstractmethod
from base64 import b64encode, b64decode

from asarPy import extract_asar, pack_asar
from crypto_plus import CryptoPlus
from crypto_plus.encrypt import encrypt_by_key, decrypt_by_key

class KeyGen(metaclass=ABCMeta):
    @abstractmethod
    def generate(self):
        pass

    @abstractmethod
    def parse(self, licenses):
        pass

    @abstractmethod
    def patch(self):
        return ""

    def run(self, patch=True):
        ciphertext_licenses = self.generate()
        print(f"ciphertext_licenses: \n{ciphertext_licenses}")
        if patch:
            patch_info = self.patch()
            if patch_info:
                print(f"patch: \n{patch_info}")
        plaintext_licenses = self.parse(ciphertext_licenses)
        print(f'plaintext_licenses: \n{plaintext_licenses}')


class XmindKeyGen(KeyGen):
    def __init__(self):
        tmp_path = os.environ['TMP']
        asar_path = pathlib.Path(tmp_path).parent.joinpath(r'Programs\Xmind\resources')
        self.asar_file = asar_path.joinpath('app.asar')
        self.asar_file_bak = asar_path.joinpath('app.asar.bak')
        self.crack_asar_dir = asar_path.joinpath('ext')
        self.main_dir = self.crack_asar_dir.joinpath("main")
        self.renderer_dir = self.crack_asar_dir.joinpath("renderer")
        self.private_key = None
        self.public_key = None
        self.old_public_key = open('old.pem').read()

    def generate(self):
        if os.path.isfile('key.pem'):
            rsa = CryptoPlus.load('key.pem')
        else:
            rsa = CryptoPlus.generate_rsa(1024)
            rsa.dump("key.pem", "new_public_key.pem")
        license_info = '{"status": "sub", "expireTime": 4093057076000, "ss": "", "deviceId": "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA"}'
        self.public_key = rsa.public_key
        self.private_key = rsa.private_key
        self.license_data = b64encode(encrypt_by_key(rsa.private_key, license_info.encode()))
        return self.license_data

    def parse(self, licenses):
        return decrypt_by_key(self.public_key, b64decode(licenses))

    def patch(self):
        # 解包
        extract_asar(str(self.asar_file), str(self.crack_asar_dir))
        shutil.copytree('crack', self.main_dir, dirs_exist_ok=True)
        # 注入
        with open(self.main_dir.joinpath('main.js'), 'rb') as f:
            lines = f.readlines()
            lines[5] = b'require("./hook")\n'
        with open(self.main_dir.joinpath('main.js'), 'wb') as f:
            f.writelines(lines)
        # 替换密钥
        old_key = f"String.fromCharCode({','.join([str(i) for i in self.old_public_key.encode()])})".encode()
        new_key = f"String.fromCharCode({','.join([str(i) for i in self.public_key.export_key()])})".encode()
        for js_file in self.renderer_dir.rglob("*.js"):
            with open(js_file, 'rb') as f:
                byte_str = f.read()
                index = byte_str.find(old_key)
                if index != -1:
                    byte_str.replace(old_key, new_key)
                    with open(js_file, 'wb') as _f:
                        _f.write(byte_str.replace(old_key, new_key))
                    print(js_file)
                    break
        # 占位符填充
        with open(self.main_dir.joinpath('hook.js'), 'r', encoding='u8') as f:
            content = f.read()
            content = content.replace("{{license_data}}", self.license_data.decode())
        with open(self.main_dir.joinpath('hook.js'), 'w', encoding='u8') as f:
            f.write(content)
        with open(self.main_dir.joinpath('hook').joinpath('crypto.js'), 'r', encoding='u8') as f:
            content = f.read()
            content = content.replace("{{old_public_key}}", self.old_public_key.replace("\n", "\\n"))
            content = content.replace("{{new_public_key}}", self.public_key.export_key().decode().replace("\n", "\\n"))
        with open(self.main_dir.joinpath('hook').joinpath('crypto.js'), 'w', encoding='u8') as f:
            f.write(content)
        # 封包
        os.remove(self.asar_file)
        pack_asar(self.crack_asar_dir, self.asar_file)
        shutil.rmtree(self.crack_asar_dir)

if __name__ == '__main__':
    XmindKeyGen().run()
```

**可在线升级，升级后再次执行脚本即可**

下载完整包后直接运行py脚本，注意不要用管理员运行。

完整包下载：[crack_xmind.zip](https://raw.githubusercontent.com/Jonxinxin/Diary/main/static/crack_xmind.zip)
项目地址：[https://github.com/qy527145/crack](https://github.com/qy527145/crack)
