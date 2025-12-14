#!/usr/bin/env python3
import ecdsa, hashlib, random, os, time, multiprocessing as mp, ctypes, sys
from typing import Dict, List, Set
import base58

GREEN = "\033[92m"
BOLD_GREEN = "\033[1;92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
RESET = "\033[0m"
DIM_GREEN = "\033[2;92m"
DIM_CYAN = "\033[2;96m"

# 字符集
ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

# Bech32字符集
BECH32_ALPHABET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
BECH32_CONST = 1

def bech32_polymod(values):
    """Bech32多项式模运算"""
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = (chk >> 25)
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= generator[i] if ((b >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp):
    """扩展HRP"""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp, data):
    """创建Bech32校验和"""
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ BECH32_CONST
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32_encode(hrp, data):
    """Bech32编码"""
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + '1' + ''.join([BECH32_ALPHABET[d] for d in combined])

def base58_encode(b: bytes) -> str:
    """Base58编码"""
    n = int.from_bytes(b, 'big')
    out = bytearray()
    while n:
        n, r = divmod(n, 58)
        out.insert(0, ALPHABET[r])
    for byte in b:
        if byte == 0:
            out.insert(0, ALPHABET[0])
        else:
            break
    return out.decode()

def base58_check_encode(version: bytes, payload: bytes) -> str:
    """Base58Check编码（带校验和）"""
    data = version + payload
    # 双重SHA256作为校验和
    checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    return base58_encode(data + checksum)

def sha256(b: bytes) -> bytes:
    """SHA256哈希"""
    return hashlib.sha256(b).digest()

def ripemd160(b: bytes) -> bytes:
    """RIPEMD-160哈希"""
    h = hashlib.new("ripemd160")
    h.update(b)
    return h.digest()

def hash160(b: bytes) -> bytes:
    """先SHA256再RIPEMD160"""
    return ripemd160(sha256(b))

class AddressGenerator:
    """地址生成器类"""
    
    def __init__(self, network: str = "mainnet"):
        """
        初始化地址生成器
        
        Args:
            network: 网络类型 ("mainnet", "testnet", "regtest")
        """
        self.network = network
        # 设置网络前缀
        if network == "mainnet":
            self.p2pkh_prefix = b'\x00'  # 1开头
            self.p2sh_prefix = b'\x05'   # 3开头
            self.bech32_hrp = "bc"       # bc1开头
        elif network == "testnet":
            self.p2pkh_prefix = b'\x6f'  # m或n开头
            self.p2sh_prefix = b'\xc4'   # 2开头
            self.bech32_hrp = "tb"       # tb1开头
        elif network == "regtest":
            self.p2pkh_prefix = b'\x6f'  # 与testnet相同
            self.p2sh_prefix = b'\xc4'
            self.bech32_hrp = "bcrt"     # bcrt1开头
        else:
            raise ValueError(f"未知网络: {network}")
    
    def get_pubkeys_from_priv(self, priv_hex: str) -> Dict[str, bytes]:
        """从私钥生成压缩和未压缩公钥"""
        sk = ecdsa.SigningKey.from_string(bytes.fromhex(priv_hex), curve=ecdsa.SECP256k1)
        vk = sk.verifying_key
        x = vk.to_string()[:32]
        y = vk.to_string()[32:]
        
        # 压缩公钥
        prefix = b'\x03' if (y[-1] & 1) else b'\x02'
        compressed_pubkey = prefix + x
        
        # 未压缩公钥
        uncompressed_pubkey = b'\x04' + vk.to_string()
        
        return {
            'compressed': compressed_pubkey,
            'uncompressed': uncompressed_pubkey,
            'priv': priv_hex
        }
    
    def pubkey_to_p2pkh(self, pubkey: bytes) -> str:
        """生成P2PKH地址（传统地址）"""
        # 1. 计算公钥哈希 (RIPEMD160(SHA256(pubkey)))
        pubkey_hash = hash160(pubkey)
        
        # 2. Base58Check编码
        return base58_check_encode(self.p2pkh_prefix, pubkey_hash)
    
    def pubkey_to_p2sh(self, pubkey: bytes) -> str:
        """生成P2SH地址（多签地址）"""
        # 1. 计算赎回脚本哈希
        # 对于P2SH-P2WPKH，先创建见证程序
        pubkey_hash = hash160(pubkey)
        witness_program = b'\x00\x14' + pubkey_hash  # 0x00 0x14 <20-byte-pubkey-hash>
        
        # 2. 计算脚本哈希
        script_hash = hash160(witness_program)
        
        # 3. Base58Check编码
        return base58_check_encode(self.p2sh_prefix, script_hash)
    
    def pubkey_to_bech32(self, pubkey: bytes) -> str:
        """生成原生SegWit地址（Bech32格式）"""
        # 1. 计算见证程序 (P2WPKH)
        pubkey_hash = hash160(pubkey)
        witness_program = bytes([0x00, 0x14]) + pubkey_hash  # 版本0，长度20
        
        # 2. 转换为5位字节数组
        data = self.convertbits(witness_program, 8, 5)
        if data is None:
            raise ValueError("转换失败")
        
        # 3. Bech32编码
        return bech32_encode(self.bech32_hrp, data)
    
    def pubkey_to_bech32m(self, pubkey: bytes) -> str:
        """生成Bech32m地址（Taproot）"""
        # Taproot地址（版本1）
        # 这里简化处理，实际需要更复杂的计算
        pubkey_hash = hash160(pubkey)
        witness_program = bytes([0x01, 0x20]) + sha256(pubkey_hash)[:32]
        
        # 转换为5位字节数组
        data = self.convertbits(witness_program, 8, 5)
        if data is None:
            raise ValueError("转换失败")
        
        # Bech32m编码（使用不同的常数）
        return self.bech32m_encode(self.bech32_hrp, data)
    
    def convertbits(self, data: bytes, frombits: int, tobits: int, pad: bool = True) -> List[int]:
        """转换位宽"""
        acc = 0
        bits = 0
        ret = []
        maxv = (1 << tobits) - 1
        
        for value in data:
            if value < 0 or (value >> frombits):
                return None
            acc = (acc << frombits) | value
            bits += frombits
            while bits >= tobits:
                bits -= tobits
                ret.append((acc >> bits) & maxv)
        
        if pad:
            if bits:
                ret.append((acc << (tobits - bits)) & maxv)
        elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
            return None
        
        return ret
    
    def bech32m_encode(self, hrp: str, data: List[int]) -> str:
        """Bech32m编码"""
        values = bech32_hrp_expand(hrp) + data
        polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 0x2bc830a3  # Bech32m常数
        checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
        return hrp + '1' + ''.join([BECH32_ALPHABET[d] for d in data + checksum])
    
    def generate_all_addresses(self, priv_hex: str) -> Dict[str, Dict[str, str]]:
        """生成所有类型的地址"""
        pubkeys = self.get_pubkeys_from_priv(priv_hex)
        
        compressed_pubkey = pubkeys['compressed']
        uncompressed_pubkey = pubkeys['uncompressed']
        
        addresses = {
            'compressed': {
                'p2pkh': self.pubkey_to_p2pkh(compressed_pubkey),
                'p2sh': self.pubkey_to_p2sh(compressed_pubkey),
                'bech32': self.pubkey_to_bech32(compressed_pubkey),
                'bech32m': self.pubkey_to_bech32m(compressed_pubkey),
                'pubkey_hex': compressed_pubkey.hex(),
                'pubkey_type': 'compressed'
            },
            'uncompressed': {
                'p2pkh': self.pubkey_to_p2pkh(uncompressed_pubkey),
                'p2sh': self.pubkey_to_p2sh(uncompressed_pubkey),
                'bech32': self.pubkey_to_bech32(uncompressed_pubkey),
                'bech32m': self.pubkey_to_bech32m(uncompressed_pubkey),
                'pubkey_hex': uncompressed_pubkey.hex(),
                'pubkey_type': 'uncompressed'
            },
            'priv': priv_hex
        }
        
        return addresses

def load_targets(filename: str = "addresses.txt") -> Set[str]:
    """加载目标地址文件"""
    if not os.path.exists(filename):
        print(f"{RED}❌ 目标地址文件不存在: {filename}{RESET}")
        print(f"{YELLOW}请创建 {filename} 文件，每行一个比特币地址{RESET}")
        print(f"{YELLOW}支持的地址格式:{RESET}")
        print(f"{YELLOW}  - P2PKH: 1开头 (如: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa){RESET}")
        print(f"{YELLOW}  - P2SH: 3开头 (如: 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy){RESET}")
        print(f"{YELLOW}  - Bech32: bc1开头 (如: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4){RESET}")
        print(f"{YELLOW}  - Bech32m: bc1p开头 (如: bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0){RESET}")
        sys.exit(1)
    
    with open(filename, "r", encoding='utf-8') as f:
        targets = set()
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if line:
                # 跳过注释行
                if line.startswith('#'):
                    continue
                # 验证地址格式（简单检查）
                if self.validate_address(line):
                    targets.add(line)
                else:
                    print(f"{YELLOW}⚠️  第{line_num}行: 可能不是有效的比特币地址: {line}{RESET}")
        
        if not targets:
            print(f"{RED}❌ 没有找到有效的比特币地址{RESET}")
            sys.exit(1)
            
        return targets

def validate_address(address: str) -> bool:
    """简单验证比特币地址格式"""
    if not address:
        return False
    
    # P2PKH地址: 1开头，长度26-35
    if address[0] == '1' and 26 <= len(address) <= 35:
        return True
    
    # P2SH地址: 3开头，长度26-35
    if address[0] == '3' and 26 <= len(address) <= 35:
        return True
    
    # Bech32地址: bc1开头，长度42-62
    if address.startswith('bc1') and 42 <= len(address) <= 62:
        return True
    
    # Bech32m地址: bc1p开头，长度62
    if address.startswith('bc1p') and len(address) == 62:
        return True
    
    # 测试网地址
    if (address[0] in 'mn2' and 26 <= len(address) <= 35) or \
       (address.startswith('tb1') and 42 <= len(address) <= 62) or \
       (address.startswith('tb1p') and len(address) == 63):
        return True
    
    return False

def print_rain_effect():
    """生成黑客帝国风格绿色随机hex雨滴"""
    s = ''.join(random.choice("0123456789ABCDEF▓▒░█") for _ in range(64))
    # 随机加噪声
    s = ''.join(
        (char if random.random() > 0.15 else random.choice("▓▒░█"))
        for char in s
    )
    return GREEN + s + RESET

def print_process_header():
    """打印处理头信息"""
    print(f"{CYAN}{'='*100}{RESET}")
    print(f"{BOLD_GREEN}🚀 比特币地址扫描进程 - 多格式支持{RESET}")
    print(f"{CYAN}{'='*100}{RESET}")

def print_address_details(addresses: Dict[str, Dict[str, str]], priv_hex: str):
    """详细打印地址生成过程"""
    print(f"\n{DIM_CYAN}{'━'*60}{RESET}")
    print(f"{BLUE}🔐 私钥: {priv_hex}{RESET}")
    print(f"{DIM_CYAN}{'━'*60}{RESET}")
    
    for pubkey_type in ['compressed', 'uncompressed']:
        addr_info = addresses[pubkey_type]
        print(f"\n{YELLOW}📋 {pubkey_type.upper()} 公钥类型:{RESET}")
        print(f"  {MAGENTA}公钥: {addr_info['pubkey_hex'][:64]}...{RESET}")
        
        print(f"  {CYAN}生成的地址:{RESET}")
        print(f"    {GREEN}• P2PKH:    {addr_info['p2pkh']}{RESET}")
        print(f"    {GREEN}• P2SH:     {addr_info['p2sh']}{RESET}")
        print(f"    {GREEN}• Bech32:   {addr_info['bech32']}{RESET}")
        print(f"    {GREEN}• Bech32m:  {addr_info['bech32m']}{RESET}")
    
    print(f"{DIM_CYAN}{'━'*60}{RESET}")

def print_match_found(match_info: Dict):
    """打印找到匹配的信息"""
    print(f"\n{RED}{'═'*100}{RESET}")
    print(f"{BOLD_GREEN}{'🔥'*10} 找到地址匹配！ {'🔥'*10}{RESET}")
    print(f"{RED}{'═'*100}{RESET}")
    
    print(f"\n{YELLOW}🎯 匹配详细信息:{RESET}")
    print(f"  {CYAN}匹配类型: {match_info['type']}{RESET}")
    print(f"  {MAGENTA}私钥: {match_info['priv']}{RESET}")
    print(f"  {GREEN}匹配地址: {match_info['address']}{RESET}")
    print(f"  {BLUE}公钥类型: {match_info['pubkey_type']}{RESET}")
    print(f"  {YELLOW}公钥: {match_info['pubkey'][:64]}...{RESET}")
    
    print(f"\n{CYAN}所有生成的地址:{RESET}")
    for addr_type, addr in match_info['all_addresses'].items():
        print(f"  • {addr_type}: {addr}")
    
    print(f"{RED}{'═'*100}{RESET}")
    
    # 声音提醒
    for _ in range(5):
        print("\a", end="", flush=True)
        time.sleep(0.1)

def worker(targets: Set[str], run_flag, stats, network: str = "mainnet"):
    """工作进程函数"""
    addr_gen = AddressGenerator(network)
    stats['checked'] = 0
    stats['matches'] = 0
    stats['last_check'] = time.time()
    
    while run_flag.value:
        try:
            # 生成随机私钥
            priv = ("%064x" % random.getrandbits(256))
            
            # 获取所有地址
            addresses = addr_gen.generate_all_addresses(priv)
            
            # 更新统计
            stats['checked'] += 1
            
            # 详细打印过程（每100个打印一次）
            if stats['checked'] % 100 == 0:
                print(f"{DIM_GREEN}[进度] 进程 {os.getpid()} - 已检查: {stats['checked']} 个私钥{RESET}")
                print_address_details(addresses, priv)
            
            # 检查匹配
            found_match = False
            match_info = None
            
            for pubkey_type in ['compressed', 'uncompressed']:
                addr_info = addresses[pubkey_type]
                
                # 检查所有地址类型
                for addr_type, addr in [
                    ('P2PKH', addr_info['p2pkh']),
                    ('P2SH', addr_info['p2sh']),
                    ('Bech32', addr_info['bech32']),
                    ('Bech32m', addr_info['bech32m'])
                ]:
                    if addr in targets:
                        found_match = True
                        match_info = {
                            'type': f"{pubkey_type.upper()} {addr_type}",
                            'priv': priv,
                            'address': addr,
                            'pubkey': addr_info['pubkey_hex'],
                            'pubkey_type': pubkey_type,
                            'all_addresses': {
                                'P2PKH': addr_info['p2pkh'],
                                'P2SH': addr_info['p2sh'],
                                'Bech32': addr_info['bech32'],
                                'Bech32m': addr_info['bech32m']
                            }
                        }
                        break
                
                if found_match:
                    break
            
            if found_match and match_info:
                stats['matches'] += 1
                print_match_found(match_info)
                
                # 写入文件
                with open("found_matches.txt", "a", encoding='utf-8') as f:
                    f.write(f"{'='*80}\n")
                    f.write(f"匹配时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"匹配类型: {match_info['type']}\n")
                    f.write(f"私钥: {match_info['priv']}\n")
                    f.write(f"地址: {match_info['address']}\n")
                    f.write(f"公钥类型: {match_info['pubkey_type']}\n")
                    f.write(f"公钥: {match_info['pubkey']}\n")
                    f.write(f"所有地址:\n")
                    for addr_type, addr in match_info['all_addresses'].items():
                        f.write(f"  {addr_type}: {addr}\n")
                    f.write(f"{'='*80}\n\n")
            
            # 随机显示雨滴效果
            if random.random() < 0.1:
                print(print_rain_effect())
            
        except Exception as e:
            print(f"{RED}❌ 错误: {e}{RESET}")
            continue

def print_stats(stats, run_flag, num_workers: int):
    """打印统计信息"""
    start_time = time.time()
    last_check_count = 0
    
    while run_flag.value:
        time.sleep(5)
        
        current_time = time.time()
        elapsed = current_time - start_time
        total_checked = stats['checked']
        
        # 计算速度
        if elapsed > 0:
            speed = total_checked / elapsed
            recent_speed = (total_checked - last_check_count) / 5 if last_check_count > 0 else speed
        else:
            speed = recent_speed = 0
        
        last_check_count = total_checked
        
        # 计算概率信息（假设有1个目标地址）
        # 比特币地址空间: 2^160
        total_address_space = 2**160
        probability = total_checked / total_address_space if total_address_space > 0 else 0
        
        print(f"\n{BLUE}{'='*60}{RESET}")
        print(f"{CYAN}📊 实时统计信息{RESET}")
        print(f"{BLUE}{'='*60}{RESET}")
        print(f"{YELLOW}运行时间: {elapsed:.1f} 秒{RESET}")
        print(f"{GREEN}工作进程数: {num_workers}{RESET}")
        print(f"{MAGENTA}已检查私钥总数: {total_checked:,}{RESET}")
        print(f"{CYAN}找到匹配数: {stats['matches']}{RESET}")
        print(f"{BLUE}检查速度: {speed:.1f} 私钥/秒 ({recent_speed:.1f} 最近){RESET}")
        print(f"{YELLOW}检查速度: {(speed * 60):.0f} 私钥/分钟{RESET}")
        print(f"{GREEN}概率: {probability:.10e}%{RESET}")
        
        if speed > 0:
            # 预计时间（按当前速度检查全部地址空间）
            remaining_keys = total_address_space - total_checked
            estimated_seconds = remaining_keys / speed
            estimated_years = estimated_seconds / (60 * 60 * 24 * 365)
            print(f"{RED}预计完成时间: {estimated_years:.2e} 年{RESET}")
        
        print(f"{BLUE}{'='*60}{RESET}\n")

def main():
    """主函数"""
    os.system("cls" if os.name == "nt" else "clear")
    
    print_process_header()
    
    # 选择网络
    print(f"{YELLOW}🌐 选择网络类型:{RESET}")
    print(f"  1. {GREEN}主网 (mainnet){RESET}")
    print(f"  2. {BLUE}测试网 (testnet){RESET}")
    print(f"  3. {MAGENTA}回归测试网 (regtest){RESET}")
    
    try:
        choice = input(f"{CYAN}请选择 (1-3, 默认1): {RESET}").strip()
        if choice == '2':
            network = "testnet"
        elif choice == '3':
            network = "regtest"
        else:
            network = "mainnet"
    except:
        network = "mainnet"
    
    # 加载目标地址
    targets = load_targets()
    print(f"\n{GREEN}✅ 已加载 {len(targets)} 个比特币地址{RESET}")
    
    # 显示地址类型统计
    addr_types = {'P2PKH': 0, 'P2SH': 0, 'Bech32': 0, 'Bech32m': 0, '其他': 0}
    for addr in targets:
        if addr.startswith('1'):
            addr_types['P2PKH'] += 1
        elif addr.startswith('3'):
            addr_types['P2SH'] += 1
        elif addr.startswith('bc1q'):
            addr_types['Bech32'] += 1
        elif addr.startswith('bc1p'):
            addr_types['Bech32m'] += 1
        else:
            addr_types['其他'] += 1
    
    print(f"{CYAN}📊 地址类型统计:{RESET}")
    for addr_type, count in addr_types.items():
        if count > 0:
            print(f"  {addr_type}: {count} 个")
    
    print(f"\n{BLUE}⚙️  配置信息:{RESET}")
    print(f"  网络类型: {network}")
    print(f"  目标地址文件: addresses.txt")
    print(f"  输出文件: found_matches.txt")
    
    # 设置工作进程数
    num_cpus = mp.cpu_count()
    print(f"\n{YELLOW}💻 系统信息:{RESET}")
    print(f"  CPU核心数: {num_cpus}")
    
    try:
        num_workers = int(input(f"{CYAN}设置工作进程数 (1-{num_cpus*2}, 默认{num_cpus}): {RESET}") or num_cpus)
        num_workers = max(1, min(num_workers, num_cpus * 2))
    except:
        num_workers = num_cpus
    
    print(f"\n{GREEN}🚀 启动 {num_workers} 个工作进程...{RESET}")
    
    # 创建共享变量
    run_flag = mp.Value(ctypes.c_bool, True)
    manager = mp.Manager()
    stats = manager.dict({'checked': 0, 'matches': 0})
    
    # 创建工作进程
    processes = []
    for i in range(num_workers):
        p = mp.Process(target=worker, args=(targets, run_flag, stats, network))
        p.start()
        processes.append(p)
        print(f"{GREEN}  进程 {i+1} 已启动 (PID: {p.pid}){RESET}")
    
    # 创建统计进程
    stat_process = mp.Process(target=print_stats, args=(stats, run_flag, num_workers))
    stat_process.start()
    
    print(f"\n{YELLOW}📈 统计进程已启动{RESET}")
    print(f"{GREEN}✅ 所有进程启动完成，开始扫描...{RESET}")
    print(f"{CYAN}{'━'*60}{RESET}")
    
    try:
        # 主进程等待
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print(f"\n{YELLOW}🛑 收到停止信号，正在停止所有进程...{RESET}")
        run_flag.value = False
        
        # 等待所有进程结束
        for p in processes:
            p.join(timeout=3)
        stat_process.join(timeout=3)
        
        print(f"{GREEN}✅ 所有进程已停止{RESET}")
        
        # 打印最终统计
        elapsed = time.time() - start_time if 'start_time' in locals() else 0
        print(f"\n{CYAN}{'='*60}{RESET}")
        print(f"{BOLD_GREEN}📊 最终统计结果{RESET}")
        print(f"{CYAN}{'='*60}{RESET}")
        print(f"{YELLOW}总运行时间: {elapsed:.1f} 秒{RESET}")
        print(f"{GREEN}工作进程数: {num_workers}{RESET}")
        print(f"{MAGENTA}检查私钥总数: {stats['checked']:,}{RESET}")
        print(f"{RED}找到匹配地址: {stats['matches']}{RESET}")
        
        if elapsed > 0:
            speed = stats['checked'] / elapsed
            print(f"{BLUE}平均速度: {speed:.1f} 私钥/秒{RESET}")
            print(f"{CYAN}平均速度: {(speed * 60):.0f} 私钥/分钟{RESET}")
        
        print(f"{GREEN}感谢使用比特币地址扫描器！{RESET}")
        print(f"{CYAN}{'='*60}{RESET}")

if __name__ == "__main__":
    # 设置随机种子
    random.seed(time.time())
    
    # 全局开始时间
    start_time = time.time()
    
    main()