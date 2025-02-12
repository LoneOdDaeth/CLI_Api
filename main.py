import click
from pymongo import MongoClient
import yara_x
import hashlib

def yara_process(rulesFile_path, file_path):
    with open(rulesFile_path, "r") as file:
        data_rules = file.read()
    
    rules = yara_x.compile(data_rules)

    with open(file_path, "rb") as file:
        data = file.read()
    
    matches = rules.scan(data)
    print(matches)
    return matches

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
            
    return sha256_hash.hexdigest()

def query_db(collection, field, data):
    client = MongoClient("mongodb://localhost:27017/")
    db = client["test1"]
    collection = db[collection]

    if field == "url":
        query = { "url": { "$regex": data, "$options": "i" } }
        result = collection.find_one(query)
        return result
    else:
        result = collection.find_one({f"{field}": data})
        return result

@click.group()
def cli():
    """Malware kontrol CLI aracı"""
    pass

@click.command(
    help="Kullanım: api_main.py check-hash --hash <HASH_TÜRÜ> --value <HASH_DEĞERİ>\n\n"
         "Belirtilen hash değerini kötü amaçlı olup olmadığını kontrol eder."
)
@click.option(
    "--hash",
    type=click.Choice(['md5', 'sha256', 'sha3-384', 'sha1', 'tlsh', 'ssdeep', 'imphash'], case_sensitive=False),
    required=True,
    help="Kontrol edilecek değer (md5, sha256, sha1, sha3-384, tlsh, ssdeep, imphash)"
)
@click.option(
    "--value",
    type=str,
    required=True,
    help="Hashlenmiş değeri girin."
)
def check_hash(hash, value):
    if not value:
        click.secho("Hata: --value parametresi gereklidir!", fg="red", bold=True)
        return
    
    if value:
        result_hash = query_db("file", hash, value)
        if result_hash:
            click.secho("Zararlı Dosya!", fg="red", bold=True)
            click.secho(f"Hash: {value}", fg="yellow")
            click.secho(f"Tür: {hash}", fg="yellow")
            click.secho(f"Dosya Adı: {result_hash.get('filename', 'Bilinmiyor')}", fg="yellow")
            click.secho(f"Tag: {', '.join(result_hash.get('tag_name', []))}", fg="yellow")
        else:
            click.secho(f"{value} Temiz!", fg="green", bold=True)
        return

@click.command( help="Kullanım: api_main.py check-url --url <URL_DEĞERİ>\n\n")
@click.option("--url", help="Kontrol edilecek URL (örn: https://example.com)")
def check_url(url):
    if url.startswith("htt"):
        result_url = query_db("url", "url", url)
        if result_url:
            click.secho(f"Zararlı URL!", fg="red", bold=True)
            click.secho(f"URL: {url}", fg="yellow")
            click.secho(f"Tür: {result_url.get('type')}", fg="yellow")
            click.secho(f"Tag: {', '.join(result_url.get('tag_name', []))}", fg="yellow")
        else:
            click.secho(f"{url} Temiz!", fg="green", bold=True)
        return
    
@click.command( help="Kullanım: api_main.py check-domain --domain <DOMAİN_DEĞERİ>\n\n")
@click.option("--domain", help="Kontrol edilecek domain (örn: example.com)")
def check_domain(domain):
    result_domain = query_db("domain", "domain", domain)
    if result_domain:
        click.secho(f"Zararlı Domain!", fg="red", bold=True)
        click.secho(f"Domain: {domain}", fg="yellow")
        click.secho(f"Tür: {result_domain.get('type')}", fg="yellow")
        click.secho(f"Tag: {', '.join(result_domain.get('tag_name', []))}", fg="yellow")
    else:
        click.secho(f"{domain} Temiz!", fg="green", bold=True)
    return

@click.command( help="Kullanım: api_main.py check-ip --ip <IP_DEĞERİ>\n\n")
@click.option("--ip", help="Kntrol edilecek IP (örn: 193.161.193.99:52354)")
def check_ip(ip):
    result_ip = query_db("ip", "ip-dst:port", ip)
    if result_ip:
        click.secho(f"Zararlı IP!", fg="red", bold=True)
        click.secho(f"IP: {ip}", fg="yellow")
        click.secho(f"Tür: {result_ip.get('type')}", fg="yellow")
        click.secho(f"Tag: {', '.join(result_ip.get('tag_name', []))}", fg="yellow")
    else:
        click.secho(f"{ip} Temiz!", fg="green", bold=True)
    return

@click.command( help="Kullanım: api_main.py check-yara --yara <YARA_DEĞERİ>\n\n")
@click.option("--yara", help="Kontrol edilecek YARA kuralı (örn: AgentTesla_DIFF_Common_Strings_01.yar)")
def check_yara(yara):
    result_yara = query_db("yara", "yara_title", yara)
    if result_yara:
        click.secho(f"Yara kuralı bulundu!", fg="red", bold=True)
        click.secho(f"Yara Kuralı: {yara}", fg="yellow")
        click.secho(f"Path: {result_yara.get('file_path')}", fg="yellow")
    else:
        click.secho(f"Yara kuralı bulunamadı: {yara}", fg="green")
    return

@click.command(help="Kullanım: api_main.py check-filepath --file <dosya dizini>\n\n")
@click.option("--file", help="Hash değeri kontrol edilir ve database de bu hash değeri var mı kontrol edilir")
def check_filePath(file):
    result_hash = calculate_sha256(file)
    result_hashValue = query_db("file", "sha256", result_hash)
    if result_hashValue:
        click.secho("Zararlı Dosya!", fg="red", bold=True)
        click.secho(f"Hash değeri: {result_hash}", fg="yellow", bold=True)
        click.secho(f"Tür: sha256", fg="yellow")
        click.secho(f"Dosya Adı: {result_hashValue.get('filename', 'Bilinmiyor')}", fg="yellow")
        click.secho(f"Tag: {', '.join(result_hashValue.get('tag_name', []))}", fg="yellow")
    else:
        click.secho(f"Hash değeri bulunamadı!", fg="green")
        click.secho(f"Hash değeri: {result_hash}", fg="yellow")
    return

@click.command(
    help="Kullanım: api_main.py check-fileyara --file <dosya dizini> --yara_title <yara başlığı>\n\n"
)
@click.option(
    "--file",
    required=True
)
@click.option(
    "--yara_title",
    type=str,
    required=True
)
def check_fileYara(file, yara_title):
    result = query_db("yara", "yara_title", yara_title)
    if result:
        yara = yara_process(result.get('yara_title'), file)
        if yara:
            click.secho("Dosya zaralı", fg="red", bold=True)
            click.secho(f"Yara kuralı: {yara_title}", fg="yellow")
            click.secho(f"İşlenen dosyanın dizini: {file}", fg="yellow")
        else:
            click.secho("Dosya zararsız", fg="green")
        return
    else:
        click.secho("Geçersiz format", fg="red")

cli.add_command(check_hash)
cli.add_command(check_domain)
cli.add_command(check_ip)
cli.add_command(check_url)
cli.add_command(check_yara)
cli.add_command(check_filePath)
cli.add_command(check_fileYara)

if __name__ == '__main__':
    cli()
