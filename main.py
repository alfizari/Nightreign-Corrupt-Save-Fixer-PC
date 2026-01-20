from tkinter import messagebox, simpledialog, ttk, filedialog
import tkinter as tk
from pathlib import Path
from main_file import decrypt_ds2_sl2, encrypt_modified_files
import os, sys, struct


item_table=None
unk_below_inventory_6=None
data=None
MERGED=False
char_name_list=[]
char_buttons=[]
current_char_path = None

WORKING_DIR = Path(os.path.dirname(os.path.abspath(__file__)))

def open_file():
    file_path = filedialog.askopenfilename(
        title="Select a save file",
        filetypes=(("Save files", "*.sl2"), ("All files", "*.*"))
    )
    if not file_path:
        return

    decrypt_ds2_sl2(file_path)
    name_to_path()
    display_character_buttons()


def name_to_path():
    global char_name_list
    char_name_list = []

    unpacked_folder = WORKING_DIR / 'decrypted_output'
    prefix = "USERDATA_0"

    for i in range(10):
        file_path = unpacked_folder / f"{prefix}{i}"
        if not file_path.exists():
            continue

        try:
            with open(file_path, "rb") as f:
                file_data = f.read()

            if len(file_data) < 0x1000:
                continue

            name = read_char_name(file_data)
            if name:
                char_name_list.append((name, file_path))

        except Exception as e:
            print(f"Error reading {file_path}: {e}")


def read_char_name(data):
    name_offset = gaprint(data) + 0x94
    max_chars = 16

    for cur in range(name_offset, name_offset + max_chars * 2, 2):
        if data[cur:cur + 2] == b'\x00\x00':
            max_chars = (cur - name_offset) // 2
            break

    raw_name = data[name_offset:name_offset + max_chars * 2]
    name = raw_name.decode("utf-16-le", errors="ignore").rstrip("\x00")
    return name if name else None

def load_character(path):
    global data,current_char_path, MERGED

    if data:
        with open(current_char_path, "wb") as f:
            f.write(data)
            print(f"Saved character file: {current_char_path}")

    MERGED = False
    current_char_path = path
    

    with open(path, "rb") as f:
        data = bytearray(f.read())

    print(f"Loaded character file: {path}")


def display_character_buttons():
    global char_buttons

    for widget in char_button_frame.winfo_children():
        widget.destroy()

    char_buttons = []

    columns = 4
    for idx, (name, path) in enumerate(char_name_list):
        row = idx // columns
        col = idx % columns

        btn = ttk.Button(
            char_button_frame,
            text=f"{idx + 1}. {name}",
            style="Char.TButton",
            command=lambda i=idx, p=path, n=name: on_character_click(i, p, n),
            width=20
        )
        btn.grid(row=row, column=col, padx=5, pady=5, sticky="nsew")
        char_buttons.append(btn)

    for c in range(columns):
        char_button_frame.columnconfigure(c, weight=1)


def on_character_click(idx, path, name):
    for b in char_buttons:
        b.configure(style="Char.TButton")

    char_buttons[idx].configure(style="Selected.TButton")
    load_character(path)

def save_file():
    global data, current_char_path
    if data is None:
        messagebox.showerror("Error", "No character file loaded.")
        return
    
    with open(current_char_path, "wb") as f:
        f.write(data)
    
    output_sl2_file=filedialog.asksaveasfilename( initialfile="NR0000.sl2", title="Save PC SL2 save as")
    if not output_sl2_file:
        return

    encrypt_modified_files(output_sl2_file)

    messagebox.showinfo("Success", f"save file saved successfully at {output_sl2_file}.")


ITEM_TYPE_EMPTY = 0x00000000
ITEM_TYPE_WEAPON = 0x80000000
ITEM_TYPE_ARMOR  = 0x90000000
ITEM_TYPE_RELIC  = 0xC0000000    

class Item:
    BASE_SIZE = 8

    def __init__(self, gaitem_handle, item_id, effect_1, effect_2, effect_3,
                 durability, unk_1, sec_effect1, sec_effect2, sec_effect3,
                 unk_2, offset, extra=None, size=BASE_SIZE):
        self.gaitem_handle = gaitem_handle
        self.item_id = item_id
        self.effect_1 = effect_1
        self.effect_2 = effect_2
        self.effect_3 = effect_3
        self.durability = durability
        self.unk_1 = unk_1
        self.sec_effect1 = sec_effect1
        self.sec_effect2 = sec_effect2
        self.sec_effect3 = sec_effect3
        self.unk_2 = unk_2
        self.offset = offset
        self.size = size
        self.padding = extra or ()

    @classmethod
    def from_bytes(cls, data_type, offset=0):
        data_len = len(data_type)

        # Check if we have enough data for the base read
        if offset + cls.BASE_SIZE > data_len:
            # Return empty item if not enough data
            return cls(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, offset, size=cls.BASE_SIZE)

        gaitem_handle, item_id = struct.unpack_from("<II", data_type, offset)
        type_bits = gaitem_handle & 0xF0000000
        cursor = offset + cls.BASE_SIZE
        size = cls.BASE_SIZE

        durability = unk_1 = unk_2 = 0
        effect_1 = effect_2 = effect_3 = 0
        sec_effect1 = sec_effect2 = sec_effect3 = 0
        padding = ()

        if gaitem_handle != 0:
            if type_bits == ITEM_TYPE_WEAPON:
                cursor += 80
                size = cursor - offset
            elif type_bits == ITEM_TYPE_ARMOR:
                cursor += 8
                size = cursor - offset
            elif type_bits == ITEM_TYPE_RELIC:
                # Check bounds before each read to handle corrupted/truncated saves
                if cursor + 8 > data_len:
                    return cls(gaitem_handle, item_id, 0, 0, 0, 0, 0, 0, 0, 0, 0, offset, size=cls.BASE_SIZE)
                durability, unk_1 = struct.unpack_from("<II", data_type, cursor)
                cursor += 8

                if cursor + 12 > data_len:
                    return cls(gaitem_handle, item_id, 0, 0, 0, durability, unk_1, 0, 0, 0, 0, offset, size=cursor-offset)
                effect_1, effect_2, effect_3 = struct.unpack_from("<III", data_type, cursor)
                cursor += 12

                if cursor + 0x1C > data_len:
                    return cls(gaitem_handle, item_id, effect_1, effect_2, effect_3, durability, unk_1, 0, 0, 0, 0, offset, size=cursor-offset)
                padding = struct.unpack_from("<7I", data_type, cursor)
                cursor += 0x1C

                if cursor + 12 > data_len:
                    return cls(gaitem_handle, item_id, effect_1, effect_2, effect_3, durability, unk_1, 0, 0, 0, 0, offset, extra=padding, size=cursor-offset)
                sec_effect1, sec_effect2, sec_effect3 = struct.unpack_from("<III", data_type, cursor)
                cursor += 12

                if cursor + 4 > data_len:
                    return cls(gaitem_handle, item_id, effect_1, effect_2, effect_3, durability, unk_1, sec_effect1, sec_effect2, sec_effect3, 0, offset, extra=padding, size=cursor-offset)
                unk_2 = struct.unpack_from("<I", data_type, cursor)[0]
                cursor += 12
                size = cursor - offset

        return cls(gaitem_handle, item_id, effect_1, effect_2, effect_3,
                   durability, unk_1, sec_effect1, sec_effect2, sec_effect3,
                   unk_2, offset, extra=padding, size=size)

    


def parse_items(data_type, start_offset, slot_count=5120):
    items = []
    offset = start_offset
    for _ in range(slot_count):
        item = Item.from_bytes(data_type, offset)
        items.append(item)
        offset += item.size
    return items, offset

def gaprint(data_type):
    global ga_relic, ga_items
    ga_items = []
    ga_relic = []
    start_offset = 0x14
    slot_count = 5120
    items, end_offset = parse_items(data_type, start_offset, slot_count)

    for item in items:
        type_bits = item.gaitem_handle & 0xF0000000
        parsed_item = (
                item.gaitem_handle,
                item.item_id,
                item.effect_1,
                item.effect_2,
                item.effect_3,
                item.sec_effect1,
                item.sec_effect2,
                item.sec_effect3,
                item.offset,
                item.size,
            )
        ga_items.append(parsed_item)

        if type_bits == ITEM_TYPE_RELIC:
            ga_relic.append(parsed_item)

    return end_offset

def parse_save():
    global data, item_table, unk_below_inventory_6

    if data is None:
        messagebox.showerror("Error", "No character file loaded.")
        return

    new_flag=False

    end=gaprint(data)

    player_data = 0x1af + end
    print('player_data:', player_data)

    magic_inventory= player_data + 0x2FC
    print('magic_inventory:', magic_inventory)

    unk_above_inevntory= magic_inventory + 0x1a5
    print('unk_above_inevntory:', unk_above_inevntory)

    player_inventory= unk_above_inevntory + 0xA810
    print('player_inventory:', player_inventory)

    unk_below_inventory= player_inventory + 0xA7
    print('unk_below_inventory:', unk_below_inventory)

    unk_below_inventory_1= unk_below_inventory + 0x100
    print('unk_below_inventory_1:', unk_below_inventory_1)

    unk_below_inventory_2 = unk_below_inventory_1 + 0x2C22
    print('unk_below_inventory_2:', unk_below_inventory_2)

    unk_below_inventory_3= unk_below_inventory_2 + 0x32c
    print('unk_below_inventory_3:', unk_below_inventory_3)

    unk_below_inventory_4= unk_below_inventory_3 + 0xE07
    print('unk_below_inventory_4:', unk_below_inventory_4)

    unk_below_inventory_5= unk_below_inventory_4 + 0x42
    print('unk_below_inventory_5:', unk_below_inventory_5)

    unk_below_inventory_6= unk_below_inventory_5+ 0xe3
    print('unk_below_inventory_6', unk_below_inventory_6)

    try:
        item_table_size = struct.unpack_from('<I', data, unk_below_inventory_6)[0]
        print('item_table_size:', item_table_size)
        a=0x8
        if item_table_size==44: #fresh save for some reason shows 44 slot but actual size is different
            print('correcting item_table_size from 44 to 0x1A69')
            item_table_size=0x1A69
            a=8
            new_flag=True
        
    except struct.error:
        print('buffer overflow')


    

    item_table= unk_below_inventory_6 + (item_table_size * 0x10) + 8
    print('item_table:', item_table)
    
    item_table_1= item_table + 0xEF0
    print('item_table_1:', item_table_1)

    try:
        item_table_1_size= struct.unpack_from('<I', data, item_table_1)[0]
        print('item_table_1_size:', item_table_1_size)
        if item_table_1_size!=0 and item_table_1_size!=0x3c:
            item_table_1_size_corrected= 0x3c
            print('correcting item_table_1_size from', item_table_1_size, 'to', item_table_1_size_corrected)
        elif item_table_1_size>0x1000:
            merge_save()
            parse_save()
            return
        else:
            item_table_1_size_corrected=item_table_1_size
    except struct.error:
        print('buffer overflow item_table_1_size')
    
    item_table_1_end= item_table_1 + 4 + (item_table_1_size_corrected*0x8)
    print('item_table_1_end:', item_table_1_end)

    item_table_2_start= item_table_1_end + 0x7c8
    print('item_table_2_start:', item_table_2_start)

    try:
        item_table_2_size= struct.unpack_from('<I', data, item_table_2_start)[0]
        print('item_table_2_size:', item_table_2_size)
        if item_table_2_size>0x1000:
            merge_save()
            parse_save()
            return
    except struct.error:
        print('buffer overflow item_table_2_size')

    item_table_2_end= item_table_2_start + 4 + (item_table_2_size*0x8)
    print('item_table_2_end:', item_table_2_end)

    item_table_3_start= item_table_2_end + 0x7bc
    print('item_table_3_start:', item_table_3_start)

    try:
        item_table_3_size= struct.unpack_from('<I', data, item_table_3_start)[0]
        print('item_table_3_size:', item_table_3_size)
        if item_table_3_size>0x1000:
            merge_save()
            parse_save()
            return
    except struct.error:
        print('buffer overflow item_table_3_size')
    
    item_table_3_end= item_table_3_start + 4 + (item_table_3_size*0x8)
    print('item_table_3_end:', item_table_3_end)

    if new_flag:
        steam_id=  item_table_3_end + 0x57f37 #fresh save fix
        print('steam id:', steam_id, data[steam_id:steam_id+8].hex())
        return
    else:
        unk_empty_0=  item_table_3_end + 0x14368 #fi\x
        print('unk_empty_0:', unk_empty_0)###########
    #####3


        try:
            unk_table_size = struct.unpack_from('<I', data, unk_empty_0)[0]
            print('unk_table_size:', unk_table_size)
        except struct.error as e:
            raise struct.error('buffer overflow: unk_table_size') from e

        # logical validation (AFTER successful unpack)
        if unk_table_size > 0x1000:
            merge_save()
            parse_save()
            return
            raise ValueError(f'invalid unk_table_size: {hex(unk_table_size)}')
        
        unk_table= unk_empty_0 + 1 +  (unk_table_size*8)
        print('unk_table:', unk_table)

        unk_data= unk_table + 0x60B
        print('unk_data:', unk_data)


        try:
            unk_data_1_size= struct.unpack_from('<I', data, unk_data)[0]
            print('unk_data_1_size:', unk_data_1_size)
        except struct.error:
            print('buffer overflow unk_data_1_size')

        unk_data_1= unk_data + 4 +(unk_data_1_size*8)
        print('unk_data_1:', unk_data_1)

        to_steam_id= unk_data_1 + 0x5879F # there is a large section behind it, no idea what it is for
        print('to_steam_id:', to_steam_id)

        
        if not MERGED:
            merge_save()
            parse_save()
            return

        if MERGED:
            data=write_steam_id(data, to_steam_id)

        messagebox.showinfo("Success", "Save file fixed successfully.")
        return
    
def ask_steam_id():
    steam_id = simpledialog.askstring(
        "Steam ID",
        "Enter your 17-digit SteamID64:"
    )
    
    if not steam_id:
        raise ValueError("Steam ID input cancelled")

    if not len(steam_id) == 17:
        messagebox.showerror("Error", "Steam ID must be exactly 17 digits")
        return ask_steam_id()

    return int(steam_id)

def write_steam_id(data: bytearray, to_steam_id: int):

    steam_id_int = ask_steam_id()

    steam_id_bytes = struct.pack("<Q", steam_id_int)

    data[to_steam_id : to_steam_id + 8] = steam_id_bytes
    return data

def merge_save():
    global data, MERGED

    MERGED=True

    print('merging item_table from external file...')

    


    def resource_path(name):
        if hasattr(sys, "_MEIPASS"):
            return os.path.join(sys._MEIPASS, name)
        return os.path.join(os.path.dirname(__file__), name)

    with open(resource_path("item_table"), "rb") as f:
        data_00 = f.read()

    print('replacing item_table at offset', unk_below_inventory_6)

    data = data[:unk_below_inventory_6] + data_00 + data[unk_below_inventory_6+len(data_00):]
    if len(data)>0x100020:
        # starting from data[-20] delete above it to get the correct size
        data = data[:0x100020]
    elif len(data)<0x100020:
        data += bytearray(b'\x00' * (0x100020 - len(data)))

    
    return


#UI Setup
root = tk.Tk()
root.title("Nightreign Save Fixer")
root.geometry("700x400")

style = ttk.Style(root)
style.configure("Char.TButton", font=("Arial", 10), padding=5)
style.configure("Selected.TButton", font=("Arial", 10), padding=5)
style.configure("Action.TButton", font=("Arial", 10, "bold"))

style = ttk.Style(root)

# Normal character button
style.configure(
    "Char.TButton",
    font=("Arial", 10),
    padding=5
)

# Selected character button (RED)
style.configure(
    "Selected.TButton",
    font=("Arial", 10),
    padding=5
)

style.map(
    "Selected.TButton",
    background=[("active", "#ff6666"), ("!active", "#cc3333")],
    foreground=[("!active", "white")]
)
main_frame = ttk.Frame(root, padding=10)
main_frame.pack(fill="both", expand=True)

action_frame = ttk.Frame(main_frame)
action_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))

action_frame.columnconfigure(0, weight=1)
action_frame.columnconfigure(1, weight=0)
action_frame.columnconfigure(2, weight=0)

open_btn = ttk.Button(
    action_frame,
    text="Open Save File",
    command=open_file,
    style="Action.TButton"
)
open_btn.grid(row=0, column=0, sticky="w")

fix_btn = ttk.Button(
    action_frame,
    text="Fix Save",
    command=parse_save,
    style="Action.TButton"
)
fix_btn.grid(row=0, column=1, padx=5)

save_btn = ttk.Button(
    action_frame,
    text="Save Fixed Save File",
    command=save_file,
    style="Action.TButton"
)
save_btn.grid(row=0, column=2)


char_container = ttk.LabelFrame(
    main_frame,
    text="Characters",
    padding=10
)
char_container.grid(row=1, column=0, sticky="nsew")

main_frame.rowconfigure(1, weight=1)
main_frame.columnconfigure(0, weight=1)

char_button_frame = ttk.Frame(char_container)
char_button_frame.pack(fill="both", expand=True)

root.mainloop()