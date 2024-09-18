使用如下python脚本提取指定文件.text段，加入到生产的exe 中混淆杀软，放在.\text文件夹中
执行如下命令
```
pip installer pefile
```
``` 
import pefile
import os
import uuid

def extract_and_save_sections(pe_path, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    pe = pefile.PE(pe_path)
    for section in pe.sections:
        section_name = section.Name.decode().rstrip('\x00')
        section_data = section.get_data()
        random_filename = f'{uuid.uuid4()}.bin'
        output_filepath = os.path.join(output_dir, f"{section_name}_{random_filename}")
        with open(output_filepath, 'wb') as file:
            file.write(section_data)
        print(f"段 {section_name} 的数据已保存到: {output_filepath}")

# 调用函数
extract_and_save_sections('1.exe', '.\\text')
```
