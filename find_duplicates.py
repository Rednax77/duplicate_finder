import os
import hashlib
from collections import defaultdict
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import subprocess
import platform
from datetime import datetime

# Define supported music file extensions
MUSIC_EXTENSIONS = {'.mp3', '.wav', '.flac', '.m4a', '.ogg'}

# Function to calculate the hash of a file
def hash_file(file_path):
    hasher = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

# Count total music files in directories
def count_music_files(directories):
    total_files = 0
    for directory in directories:
        for root, _, files in os.walk(directory):
            total_files += sum(1 for file in files if os.path.splitext(file)[1].lower() in MUSIC_EXTENSIONS)
    return total_files

# Function to open file in its location
def open_file_location(file_path):
    if not os.path.exists(file_path):
        messagebox.showerror("Error", f"File does not exist: {file_path}")
        return
        
    try:
        if platform.system() == "Windows":
            subprocess.run(['explorer', '/select,', os.path.normpath(file_path)])
        elif platform.system() == "Darwin":
            subprocess.run(['open', '-R', file_path])
        else:
            directory = os.path.dirname(file_path)
            if os.path.exists(directory):
                subprocess.run(['xdg-open', directory])
            else:
                messagebox.showerror("Error", f"Directory does not exist: {directory}")
    except Exception as e:
        messagebox.showerror("Error", f"Error opening file location: {e}")

# Function to save deleted files list to a text file
def save_deleted_files_list(deleted_files):
    if not deleted_files:
        messagebox.showinfo("Info", "No files to save.")
        return
        
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_filename = f"deleted_files_{timestamp}.txt"
    
    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        initialfile=default_filename,
        title="Save Deleted Files List"
    )
    
    if not file_path:
        return
        
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(f"Deleted Files - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*80 + "\n\n")
            for file_path in deleted_files:
                f.write(f"{file_path}\n")
        
        messagebox.showinfo("Success", f"Deleted files list saved to:\n{file_path}")
        
        if messagebox.askyesno("Open File", "Would you like to open the saved file?"):
            try:
                if platform.system() == "Windows":
                    os.startfile(file_path)
                elif platform.system() == "Darwin":
                    subprocess.run(['open', file_path])
                else:
                    subprocess.run(['xdg-open', file_path])
            except Exception as e:
                messagebox.showerror("Error", f"Error opening file: {e}")
    
    except Exception as e:
        messagebox.showerror("Error", f"Error saving file: {e}")

class DuplicateFinderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Duplicate Music File Finder")
        self.root.geometry("800x600")
        self.root.minsize(600, 400)
        
        # Configure dark theme
        self.style = ttk.Style()
        self.setup_dark_theme()
        
        self.directories = []
        self.check_vars = {}
        self.recently_deleted_files = []
        self.group_check_vars = defaultdict(list)
        self.is_scanning = False
        self.processed_files = set()  # Track processed file paths to avoid duplicates
        
        # Create main frame
        self.main_frame = ttk.Frame(self.root, padding="10", style='SoftMain.TFrame')
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Directory selection
        ttk.Label(self.main_frame, text="Select directories to scan for duplicates:", 
                 style='SoftMain.TLabel').grid(row=0, column=0, columnspan=2, pady=5, sticky=tk.W)
        
        self.dir_listbox = tk.Listbox(self.main_frame, width=80, height=5, 
                                    bg='#2b2b2b', fg='white', 
                                    selectbackground='#4a4a4a', highlightthickness=0)
        self.dir_listbox.grid(row=1, column=0, columnspan=2, pady=5, sticky=(tk.W, tk.E))
        
        btn_frame = ttk.Frame(self.main_frame, style='SoftMain.TFrame')
        btn_frame.grid(row=2, column=0, columnspan=2, pady=5, sticky=(tk.W, tk.E))
        ttk.Button(btn_frame, text="Add Directory", command=self.add_directory, 
                  style='SoftDark.TButton').pack(side=tk.LEFT, padx=5)
        self.scan_button = ttk.Button(btn_frame, text="Scan for Duplicates", command=self.start_scan, 
                                    style='SoftDark.TButton')
        self.scan_button.pack(side=tk.LEFT, padx=5)
        self.stop_button = ttk.Button(btn_frame, text="Stop Scan", command=self.stop_scan, 
                                    state='disabled', style='SoftDark.TButton')
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        # Progress bar and label
        self.progress_frame = ttk.LabelFrame(self.main_frame, text="Scanning Progress", 
                                           padding="10", style='SoftMain.TLabelframe')
        self.progress_frame.grid(row=3, column=0, columnspan=2, pady=5, sticky=(tk.W, tk.E))
        
        self.progress_label = ttk.Label(self.progress_frame, text="Progress: 0%", 
                                      style='SoftMain.TLabel')
        self.progress_label.grid(row=0, column=0, pady=5, sticky=tk.W)
        
        self.progress_bar = ttk.Progressbar(self.progress_frame, length=400, mode='determinate')
        self.progress_bar.grid(row=1, column=0, pady=5, sticky=(tk.W, tk.E))
        
        # Duplicate count label
        self.duplicate_count_label = ttk.Label(self.main_frame, text="Duplicate Groups Found: 0", 
                                              style='SoftMain.TLabel')
        self.duplicate_count_label.grid(row=4, column=0, columnspan=2, pady=5, sticky=tk.W)
        
        # Results frame
        self.results_frame = ttk.LabelFrame(self.main_frame, text="Duplicate Files", 
                                          padding="10", style='SoftMain.TLabelframe')
        self.results_frame.grid(row=5, column=0, columnspan=2, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.canvas = tk.Canvas(self.results_frame, bg='#2b2b2b', highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(self.results_frame, orient=tk.VERTICAL, command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas, style='SoftMain.TFrame')
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        
        # Configure weights for proper scaling
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.columnconfigure(1, weight=1)
        self.main_frame.rowconfigure(5, weight=1)
        self.progress_frame.columnconfigure(0, weight=1)
        self.results_frame.columnconfigure(0, weight=1)
        self.results_frame.rowconfigure(0, weight=1)
        btn_frame.columnconfigure(0, weight=1)
        btn_frame.columnconfigure(1, weight=1)

    def setup_dark_theme(self):
        # Use a base theme that allows better customization
        self.style.theme_use('clam')
        
        # Soft frame style with rounded corners and shadow effect
        self.style.configure('SoftMain.TFrame', 
                           background='#2b2b2b',
                           relief='flat',
                           borderwidth=2,
                           padding=5)
        self.style.map('SoftMain.TFrame',
                      background=[('active', '#333333')])
        
        # Soft label style
        self.style.configure('SoftMain.TLabel', 
                           background='#2b2b2b', 
                           foreground='white',
                           padding=2)
        
        # Soft labelframe style
        self.style.configure('SoftMain.TLabelframe', 
                           background='#2b2b2b',
                           foreground='white',
                           borderwidth=2,
                           relief='groove',
                           padding=5)
        self.style.configure('SoftMain.TLabelframe.Label', 
                           background='#2b2b2b', 
                           foreground='white',
                           padding=2)
        
        # Soft button style with rounded corners and shadow
        self.style.configure('SoftDark.TButton', 
                           background='#4a4a4a',  # Dark gray background
                           foreground='white',    # White text
                           bordercolor='#666666',
                           darkcolor='#4a4a4a',
                           lightcolor='#5a5a5a',
                           relief='flat',
                           padding=6,  # Increased padding for softer look
                           borderwidth=2)
        self.style.map('SoftDark.TButton',
                      background=[('active', '#5a5a5a'), ('disabled', '#3a3a3a')],
                      foreground=[('active', 'white'), ('disabled', '#aaaaaa')],
                      relief=[('active', 'raised')])  # Slight raise effect for shadow
        
        # Configure progressbar
        self.style.configure('Horizontal.TProgressbar',
                           background='#4a4a4a',
                           troughcolor='#2b2b2b',
                           bordercolor='#2b2b2b',
                           padding=2)
        
        # Configure scrollbar to be fully white
        self.style.configure('Vertical.TScrollbar',
                           background='white',  # White scrollbar
                           troughcolor='white',  # White background
                           arrowcolor='black',  # Black arrows for visibility
                           borderwidth=2,
                           relief='flat')
        self.style.map('Vertical.TScrollbar',
                      background=[('active', '#e0e0e0')],  # Slightly darker white when active
                      troughcolor=[('active', 'white')])
        
        # Configure checkbutton
        self.style.configure('TCheckbutton',
                           background='#2b2b2b',
                           foreground='white',
                           padding=2)
        self.style.map('TCheckbutton',
                      background=[('active', '#2b2b2b')],
                      foreground=[('active', 'white')])
        
        self.root.configure(bg='#2b2b2b')

    def add_directory(self):
        directory = filedialog.askdirectory(title="Select a directory to scan")
        if directory and directory not in self.directories:
            self.directories.append(directory)
            self.dir_listbox.insert(tk.END, directory)

    def manage_group_selection(self, hash_val, selected_var):
        group_vars = self.group_check_vars[hash_val]
        for var in group_vars:
            if var != selected_var and var.get():
                var.set(False)

    def start_scan(self):
        if not self.directories:
            messagebox.showwarning("Warning", "Please select at least one directory to scan!")
            return
        
        self.scan_button.config(state='disabled')
        self.stop_button.config(state='normal')
        self.is_scanning = True
        self.processed_files.clear()  # Clear the set of processed files
        
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        
        self.check_vars = {}
        self.group_check_vars.clear()
        self.recently_deleted_files = []
        
        self.total_files = count_music_files(self.directories)
        if self.total_files == 0:
            messagebox.showinfo("Info", "No music files found in the selected directories!")
            self.scan_button.config(state='normal')
            self.stop_button.config(state='disabled')
            return
        
        self.progress_bar['maximum'] = self.total_files
        self.progress_bar['value'] = 0
        self.progress_label.config(text="Progress: 0%")
        self.duplicate_count_label.config(text="Duplicate Groups Found: 0")
        
        self.hash_dict = defaultdict(list)
        self.current_file_count = 0
        
        self.scan_files(self.total_files)

    def stop_scan(self):
        self.is_scanning = False
        self.stop_button.config(state='disabled')
        self.scan_button.config(state='normal')
        self.progress_label.config(text="Scan Stopped")
        messagebox.showinfo("Info", "Scan stopped. Showing partial results.")
        self.display_results()

    def scan_files(self, total_files):
        if not self.is_scanning:
            return

        files_processed = 0
        max_files_per_cycle = 10

        for directory in self.directories:
            for root, _, files in os.walk(directory):
                for file in files:
                    if not self.is_scanning:
                        return
                        
                    if os.path.splitext(file)[1].lower() in MUSIC_EXTENSIONS:
                        file_path = os.path.join(root, file)
                        # Skip if this file has already been processed
                        if file_path in self.processed_files:
                            continue
                        self.processed_files.add(file_path)
                        
                        file_hash = hash_file(file_path)
                        self.hash_dict[file_hash].append(file_path)
                        
                        self.current_file_count += 1
                        files_processed += 1
                        
                        # Update progress, ensuring it doesn't exceed 100%
                        progress = min(self.current_file_count / total_files * 100, 100)
                        self.progress_bar['value'] = min(self.current_file_count, total_files)
                        self.progress_label.config(text=f"Progress: {progress:.1f}%")
                        self.root.update()
                        
                        # Stop if we've processed all expected files
                        if self.current_file_count >= total_files:
                            self.is_scanning = False
                            self.stop_button.config(state='disabled')
                            self.scan_button.config(state='normal')
                            self.display_results()
                            return
                        
                        if files_processed >= max_files_per_cycle:
                            self.root.after(10, lambda: self.scan_files(total_files))
                            return

        # If we exit the loops naturally, ensure we stop scanning
        self.is_scanning = False
        self.stop_button.config(state='disabled')
        self.scan_button.config(state='normal')
        self.progress_label.config(text="Progress: 100%")
        self.display_results()

    def display_results(self):
        duplicates = {hash_val: paths for hash_val, paths in self.hash_dict.items() if len(paths) > 1}
        
        # Update the duplicate count label
        duplicate_count = len(duplicates)
        self.duplicate_count_label.config(text=f"Duplicate Groups Found: {duplicate_count}")
        
        if not duplicates:
            ttk.Label(self.scrollable_frame, text="No duplicates found!", 
                     style='SoftMain.TLabel').pack(pady=10)
        else:
            batch_frame = ttk.Frame(self.scrollable_frame, style='SoftMain.TFrame')
            batch_frame.pack(fill=tk.X, pady=5)
            
            ttk.Button(batch_frame, text="Select All", command=self.select_all, 
                      style='SoftDark.TButton').pack(side=tk.LEFT, padx=5)
            ttk.Button(batch_frame, text="Deselect All", command=self.deselect_all, 
                      style='SoftDark.TButton').pack(side=tk.LEFT, padx=5)
            ttk.Button(batch_frame, text="Delete Selected", command=self.delete_selected, 
                      style='SoftDark.TButton').pack(side=tk.LEFT, padx=5)
            ttk.Button(batch_frame, text="Save Deleted Files List", 
                      command=lambda: save_deleted_files_list(self.recently_deleted_files),
                      style='SoftDark.TButton').pack(side=tk.LEFT, padx=5)
            
            ttk.Separator(self.scrollable_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=5)
            
            self.group_frames = {}
            
            for hash_val, file_list in duplicates.items():
                group_frame = ttk.LabelFrame(self.scrollable_frame, 
                                          text=f"Duplicates (hash: {hash_val[:8]}...)",
                                          style='SoftMain.TLabelframe')
                group_frame.pack(fill=tk.X, pady=5, padx=5, anchor="w")
                self.group_frames[hash_val] = group_frame
                
                # Only show groups with more than one file
                if len(file_list) > 1:
                    for i, file_path in enumerate(file_list, 1):
                        file_frame = ttk.Frame(group_frame, style='SoftMain.TFrame')
                        file_frame.pack(fill=tk.X, pady=2)
                        
                        var = tk.BooleanVar(value=False)
                        self.check_vars[file_path] = var
                        self.group_check_vars[hash_val].append(var)
                        
                        check = ttk.Checkbutton(
                            file_frame, 
                            variable=var,
                            command=lambda h=hash_val, v=var: self.manage_group_selection(h, v)
                        )
                        check.pack(side=tk.LEFT, padx=2)
                        
                        info_frame = ttk.Frame(file_frame, style='SoftMain.TFrame')
                        info_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
                        
                        ttk.Label(info_frame, text=f"{i}. {file_path}", wraplength=550, 
                                style='SoftMain.TLabel').pack(anchor="w", padx=5)
                        
                        btn_frame = ttk.Frame(file_frame, style='SoftMain.TFrame')
                        btn_frame.pack(side=tk.RIGHT)
                        
                        ttk.Button(
                            btn_frame, 
                            text="Open Location", 
                            command=lambda path=file_path: open_file_location(path),
                            style='SoftDark.TButton'
                        ).pack(side=tk.LEFT, padx=2)
                        
                        ttk.Button(
                            btn_frame, 
                            text="Delete", 
                            command=lambda path=file_path, f=file_frame, h=hash_val: self.delete_file(path, f, h),
                            style='SoftDark.TButton'
                        ).pack(side=tk.LEFT, padx=2)

    def select_all(self):
        for hash_val in self.group_check_vars:
            group_vars = self.group_check_vars[hash_val]
            if group_vars:
                found_selected = False
                for var in group_vars:
                    if not found_selected and not var.get():
                        var.set(True)
                        found_selected = True
                    else:
                        var.set(False)

    def deselect_all(self):
        for var in self.check_vars.values():
            var.set(False)

    def delete_selected(self):
        selected_files = [path for path, var in self.check_vars.items() if var.get()]
        if not selected_files:
            messagebox.showinfo("Info", "No files selected for deletion.")
            return
            
        if messagebox.askyesno("Confirm Batch Delete", f"Are you sure you want to delete {len(selected_files)} selected files?"):
            deleted_files = []
            error_files = []
            
            for file_path in selected_files:
                try:
                    file_hash = None
                    for hash_val, paths in self.hash_dict.items():
                        if file_path in paths:
                            file_hash = hash_val
                            break
                    
                    os.remove(file_path)
                    deleted_files.append(file_path)
                    self.recently_deleted_files.append(file_path)
                    
                    if file_hash:
                        self.hash_dict[file_hash].remove(file_path)
                        if len(self.hash_dict[file_hash]) == 1 and file_hash in self.group_frames:
                            self.group_frames[file_hash].destroy()
                    
                    for widget in self.scrollable_frame.winfo_descendants():
                        if isinstance(widget, ttk.Label) and file_path in widget.cget("text"):
                            widget.master.master.destroy()
                            break
                            
                except Exception as e:
                    error_files.append(file_path)
                    print(f"Error deleting {file_path}: {e}")
            
            if not error_files:
                result = messagebox.askyesno("Success", 
                    f"Successfully deleted {len(deleted_files)} files.\n\nWould you like to save a list of the deleted files?")
                if result:
                    save_deleted_files_list(deleted_files)
            else:
                result = messagebox.askyesno("Partial Success", 
                    f"Deleted {len(deleted_files)} files, but encountered errors with {len(error_files)} files.\n\nWould you like to save a list of the successfully deleted files?")
                if result:
                    save_deleted_files_list(deleted_files)
            
            self.check_vars = {k: v for k, v in self.check_vars.items() if k not in deleted_files}
            self.group_check_vars = defaultdict(list)
            for hash_val, paths in self.hash_dict.items():
                for path in paths:
                    if path in self.check_vars:
                        self.group_check_vars[hash_val].append(self.check_vars[path])

    def delete_file(self, file_path, frame, hash_val):
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete:\n{file_path}?"):
            try:
                os.remove(file_path)
                self.recently_deleted_files.append(file_path)
                
                result = messagebox.askyesno("Success", 
                    f"Deleted: {file_path}\n\nWould you like to save a log of deleted files?")
                if result:
                    save_deleted_files_list([file_path])
                
                self.hash_dict[hash_val].remove(file_path)
                if file_path in self.check_vars:
                    del self.check_vars[file_path]
                
                frame.destroy()
                if len(self.hash_dict[hash_val]) == 1 and hash_val in self.group_frames:
                    self.group_frames[hash_val].destroy()
                    
                self.group_check_vars[hash_val] = [
                    var for var in self.group_check_vars[hash_val] 
                    if var in self.check_vars.values()
                ]
                    
            except Exception as e:
                messagebox.showerror("Error", f"Error deleting {file_path}: {e}")

def main():
    root = tk.Tk()
    app = DuplicateFinderApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()