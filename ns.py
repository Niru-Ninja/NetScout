# ns.py
from cli.commander import ScannerCLI
from core.database import init_db

if __name__ == "__main__":
    init_db()      # ← CREA LAS TABLAS SI FALTAN
    ScannerCLI().cmdloop()