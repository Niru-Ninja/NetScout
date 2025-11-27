# cli/commander.py

import cmd2
from cmd2 import Cmd, with_argument_list
from core.scanner import scan_network
from core.iptools import is_valid_ip, expand_range
from core.database import add_ip, add_port, get_results, create_scan, get_conn, save_scan_ip
from core.plugins import load_plugins, make_save_function
import os

class ScannerCLI(Cmd):
    intro = "Bienvenido a NetScout — escriba help o ? para ver comandos\n"
    prompt = "(netscout) "

    def __init__(self):
        super().__init__()

        # Config opciones
        self.settings = {
            "ips": [],
            "ports": [80, 443],
            "timeout": 1.0,
            "threads": 50,
            "rate": 200,
            "plugins": []  # <<--- LISTA de nombres habilitados
        }

        # Plugins disponibles
        self.available_plugins = [name for name, _ in load_plugins()]

        # Diccionario interno con estado
        self.plugins = {name: {"enabled": False} for name in self.available_plugins}

        # Sincronizar plugins habilitados
        for name in self.settings["plugins"]:
            if name in self.plugins:
                self.plugins[name]["enabled"] = True

    # --- SET COMMAND ---
    @with_argument_list
    def do_set(self, args):
        if len(args) < 2:
            self.perror("Uso: set <opcion> <valor>")
            return

        key = args[0]
        value = args[1:]

        if key not in self.settings:
            self.perror(f"Opción desconocida: {key}")
            return

        # Conversión automática
        if key == "timeout":
            self.settings[key] = float(value[0])
        elif key in ("threads", "rate"):
            self.settings[key] = int(value[0])
        elif key == "ports":
            self.settings[key] = [int(v) for v in value]
        elif key == "ips":
            new_ips = []

            for item in value:
                # archivo.txt
                if os.path.isfile(item):
                    with open(item, "r") as f:
                        for line in f:
                            ip = line.strip()
                            if "-" in ip:   # rango dentro del archivo
                                new_ips.extend(expand_range(ip))
                            elif is_valid_ip(ip):
                                new_ips.append(ip)
                            else:
                                self.perror(f"IP inválida en archivo: {ip}")
                    continue

                # rango A-B
                if "-" in item:
                    try:
                        new_ips.extend(expand_range(item))
                    except Exception as e:
                        self.perror(f"Rango inválido: {item} ({e})")
                    continue

                # IP suelta
                if is_valid_ip(item):
                    new_ips.append(item)
                else:
                    self.perror(f"IP inválida: {item}")

            self.settings[key] = list(dict.fromkeys(new_ips))  # eliminar duplicados
            self.poutput(f"{key} cargó {len(self.settings[key])} IPs")


        self.poutput(f"{key} = {self.settings[key]}")

    # --- SHOW OPTIONS ---
    def do_show(self, arg):
        arg = arg.strip()

        if arg == "options":
            self._show_options()
        elif arg == "ips":
            self._show_ips()
        elif arg == "results":
            self._show_results()
        elif arg == "scans":
            self._show_scans()
        elif arg.startswith("results scan "):
            scan_id = int(arg.split()[2])
            self._show_results_scan(scan_id)
        elif arg.strip() == "plugins":
            self.poutput("\nPlugins disponibles:")
            for name in self.available_plugins:
                mark = "[X]" if self.plugins[name]["enabled"] else "[ ]"
                self.poutput(f" {mark} {name}")
            self.poutput("")
            return
        else:
            self.perror("Uso: show options | show ips | show results | show scans")


    def _show_options(self):
        self.poutput("\nOpciones actuales:")
        for k, v in self.settings.items():
            if k == "ips":
                count = len(v)
                if count == 0:
                    self.poutput("  ips       : []")
                elif count > 10:
                    self.poutput(f"  ips       : {count} IPs (usar 'show ips')")
                else:
                    self.poutput(f"  ips       : {v}")
            else:
                self.poutput(f"  {k:10}: {v}")
        self.poutput("")


    def _show_ips(self):
        ips = self.settings["ips"]
        self.poutput(f"\nTotal IPs: {len(ips)}\n")
        for ip in ips:
            self.poutput(ip)
        self.poutput("")


    def _show_results(self):
        rows = get_results()

        if not rows:
            self.poutput("\nNo hay resultados guardados.\n")
            return

        self.poutput("\n=== Resultados del escaneo ===\n")

        last_ip = None
        for row in rows:
            ip = row["ip"]
            port = row["port"]

            if ip != last_ip:
                self.poutput(f"{ip}:")
                last_ip = ip

            if port is not None:
                self.poutput(f"    - {port}")
            else:
                self.poutput("    (sin puertos abiertos)")
        self.poutput("")


    def _show_scans(self):
        from core.database import list_scans
        scans = list_scans()

        if not scans:
            self.poutput("No hay scans registrados.")
            return
        self.poutput("\nScans disponibles:")
        for sid, ts in scans:
            self.poutput(f" {sid}: {ts}")
        self.poutput("")


    def do_enable(self, arg):
        """
        enable <plugin>
        enable plugin <plugin>
        enable plugin <p1> <p2> <p3>
        """
        args = arg.split()
        if not args:
            self.perror("Uso: enable <plugin> | enable plugin <plugin1> <plugin2>")
            return

        if args[0] == "plugin":
            args = args[1:]  # permite "enable plugin X"

        for name in args:
            if name not in self.plugins:
                self.perror(f"Plugin no encontrado: {name}")
                continue

            self.plugins[name]["enabled"] = True

            # actualizar settings
            if name not in self.settings["plugins"]:
                self.settings["plugins"].append(name)

            self.poutput(f"[+] Plugin habilitado: {name}")


    def do_disable(self, arg):
        """
        disable <plugin>
        disable plugin <plugin>
        disable all
        """
        args = arg.split()
        if not args:
            self.perror("Uso: disable <plugin> | disable all")
            return

        # disable all plugins
        if args[0] == "all":
            for name in self.plugins:
                self.plugins[name]["enabled"] = False
            self.settings["plugins"].clear()
            self.poutput("[+] Todos los plugins fueron deshabilitados")
            return

        # permite "disable plugin X"
        if args[0] == "plugin":
            args = args[1:]

        for name in args:
            if name not in self.plugins:
                self.perror(f"Plugin no encontrado: {name}")
                continue

            self.plugins[name]["enabled"] = False

            if name in self.settings["plugins"]:
                self.settings["plugins"].remove(name)

            self.poutput(f"[-] Plugin deshabilitado: {name}")


    # --- AUTOCOMPLETADO PARA ENABLE ---
    def complete_enable(self, text, line, begidx, endidx):
        """
        Autocompleta:
            enable <plugin>
            enable plugin <plugin>
        """
        parts = line.split()

        # Si el usuario escribió: "enable plugin "
        if len(parts) == 2 and parts[1].startswith("plugin"):
            return ["plugin"]

        # Si escribió: "enable plugin <TAB>"
        if len(parts) == 3 and parts[1] == "plugin":
            return [p for p in self.plugins.keys() if p.startswith(text)]

        # Caso simple: "enable <TAB>"
        if len(parts) == 2:
            return [p for p in self.plugins.keys() if p.startswith(text)]

        return []


    # --- AUTOCOMPLETADO PARA DISABLE ---
    def complete_disable(self, text, line, begidx, endidx):
        """
        Autocompleta:
            disable <plugin>
            disable plugin <plugin>
            disable all
        """
        parts = line.split()

        # disable all
        if len(parts) == 2 and "all".startswith(text):
            return ["all"]

        # Si el usuario escribió: "disable plugin "
        if len(parts) == 2 and parts[1].startswith("plugin"):
            return ["plugin"]

        # "disable plugin <TAB>"
        if len(parts) == 3 and parts[1] == "plugin":
            return [p for p in self.plugins.keys() if p.startswith(text)]

        # Caso simple: "disable <TAB>"
        if len(parts) == 2:
            return [p for p in self.plugins.keys() if p.startswith(text)]

        return []


    # --- RUN ---
    def do_run(self, arg):
        parts = arg.split()
        if arg.strip() == "scan":
            return self._run_scan_real()
        elif parts[:3] == ["plugins", "on", "file"]:
            if len(parts) != 4:
                self.perror("Uso: run plugins on file <ruta.txt>")
                return
            path = parts[3]
            return self._run_plugins_on_file(path)
        elif parts[:2] == ["plugins", "on"]:
            if len(parts) != 3:
                self.perror("Uso: run plugins on <scan_id>")
                return
            try:
                scan_id = int(parts[2])
            except:
                self.perror("scan_id debe ser un número")
                return
            return self._run_plugins_on_scan(scan_id)
        else:
            self.perror("Uso: run scan | run plugins on <scan_id> | run plugins on file <path>")


    def _run_plugins_on_scan(self, scan_id):
        self.poutput(f"\nEjecutando plugins sobre scan {scan_id}...\n")

        enabled = [name for name, st in self.plugins.items() if st["enabled"]]
        plugins = [(name, p) for name, p in load_plugins() if name in enabled]


        # Cargar IPs del scan
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT ips.ip, ports.port FROM ips JOIN ports ON ips.id = ports.ip_id WHERE ports.scan_id = ?", (scan_id,))
        rows = cur.fetchall()
        conn.close()

        # Agrupar: ip -> puertos
        data = {}
        for ip, port in rows:
            data.setdefault(ip, []).append(port)

        # Ejecutar plugins
        for name, plugin in plugins:
            save = make_save_function(scan_id, name)

            for ip, ports in data.items():
                try:
                    plugin.run(ip, ports, scan_id, save)
                except Exception as e:
                    self.poutput(f"[!] Error en plugin {name}: {e}")

        self.poutput("\nPlugins ejecutados sobre el scan.\n")


    def _run_plugins_on_file(self, path):
        """Permite ejecutar plugins sobre una lista de IPs dadas en un archivo,
        sin escanear puertos ni crear un nuevo scan."""

        if not os.path.isfile(path):
            self.perror(f"Archivo no encontrado: {path}")
            return

        # Cargar IPs del archivo
        ips = []
        with open(path, "r") as f:
            for line in f:
                ip = line.strip()
                if ip and is_valid_ip(ip):
                    ips.append(ip)
                else:
                    self.poutput(f"[!] IP inválida en archivo: {ip}")

        if not ips:
            self.perror("El archivo no contiene IPs válidas.")
            return

        # Crear un nuevo scan_id lógico (no escanea puertos)
        scan_id = create_scan()
        self.poutput(f"\n[*] Nuevo scan_id creado para plugins: {scan_id}\n")

        # Guardamos IPs en la tabla scan_ips, sin puertos
        from core.database import add_ip, save_scan_ip
        for ip in ips:
            ip_id = add_ip(ip)
            save_scan_ip(scan_id, ip_id)

        # Ejecutar plugins habilitados
        enabled = self.settings["plugins"]
        plugins = [(name, p) for name, p in load_plugins() if name in enabled]

        if not plugins:
            self.poutput("No hay plugins habilitados.")
            return

        self.poutput(f"Ejecutando plugins sobre {len(ips)} IPs...\n")

        for name, plugin in plugins:
            save = make_save_function(scan_id, name)

            for ip in ips:
                try:
                    plugin.run(ip, [], scan_id, save)   # sin puertos
                except Exception as e:
                    self.poutput(f"[!] Error en plugin {name}: {e}")

        self.poutput(f"\nPlugins ejecutados. Nuevo scan_id: {scan_id}\n")


    def _run_scan_real(self):
        """Ejecuta el escaneo real usando core/scanner.py"""

        ips     = self.settings["ips"]
        ports   = self.settings["ports"]
        threads = self.settings["threads"]
        rate    = self.settings["rate"]
        timeout = self.settings["timeout"]

        if not ips:
            self.perror("No hay IPs configuradas. Use: set ips <ip1> <ip2> ...")
            return

        scan_id = create_scan()
        self.poutput(f"[*] Nuevo scan_id creado: {scan_id}")
        self.poutput("\n=== NetScout — Escaneo iniciado ===\n")

        def cb_ip_start(ip):
            self.poutput(f"[+] Iniciando {ip}")
            # Linkeamos dirección ip a tabla de scan:
            ip_id = add_ip(ip)
            save_scan_ip(scan_id, ip_id)

        def cb_port_open(ip, port):
            self.poutput(f"    └── Puerto abierto: {port}")
            ip_id = add_ip(ip)
            add_port(ip_id, port, scan_id)

        def cb_ip_end(ip, open_ports):
            if open_ports:
                self.poutput(f"[=] {ip} finalizado: {open_ports}")
            else:
                self.poutput(f"[-] {ip} finalizado sin puertos abiertos")
        
        # Ejecutamos el escaneo real
        try:
            results = scan_network(
                ips=ips,
                ports=ports,
                max_workers=threads,
                rate_sec=rate,
                timeout=timeout,
                on_ip_start=cb_ip_start,
                on_port_open=cb_port_open,
                on_ip_end=cb_ip_end,
            )
        except Exception as e:
            self.perror(f"Error al escanear: {e}")
            return

        self.poutput("\n=== Escaneo base terminado ===\n")

        
        self.poutput("\n=== Ejecutando plugins ===")
        enabled = self.settings["plugins"]
        plugins = [(name, plugin) for name, plugin in load_plugins() if name in enabled]

        for name, plugin in plugins:
            save = make_save_function(scan_id, name)
            for ip, open_ports in results.items():
                try:
                    plugin.run(ip, open_ports, scan_id, save)
                except Exception as e:
                    self.poutput(f"[!] Error en plugin {name}: {e}")
        self.poutput("\n=== Plugins ejecutados ===\n")


    def do_exit(self, arg):
        self.poutput("¡Hasta luego!")
        return True