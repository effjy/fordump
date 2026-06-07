#include <gtk/gtk.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "forensics.h"

// CSS Styling definitions
const char *custom_css = 
    "window { background-color: #111827; color: #f3f4f6; font-family: 'Inter', 'Outfit', sans-serif; }\n"
    "notebook { background-color: #1f2937; border: 1px solid #374151; border-radius: 8px; }\n"
    "notebook tab { background-color: #111827; color: #9ca3af; padding: 12px 24px; font-weight: 600; border: none; }\n"
    "notebook tab:checked { background-color: #1f2937; color: #3b82f6; border-bottom: 3px solid #3b82f6; }\n"
    "button.suggested-action { background-image: linear-gradient(to right, #3b82f6, #2563eb); color: white; border-radius: 6px; padding: 10px 20px; border: none; font-weight: bold; }\n"
    "button.suggested-action:hover { background-image: linear-gradient(to right, #2563eb, #1d4ed8); }\n"
    "button.suggested-action:disabled { background: #4b5563; color: #9ca3af; }\n"
    "button { background-color: #374151; color: white; border-radius: 6px; padding: 8px 16px; border: 1px solid #4b5563; }\n"
    "button:hover { background-color: #4b5563; }\n"
    "button.destructive-action { background-image: linear-gradient(to right, #ef4444, #dc2626); color: white; border-radius: 6px; padding: 10px 20px; border: none; font-weight: bold; }\n"
    "button.destructive-action:hover { background-image: linear-gradient(to right, #dc2626, #b91c1c); }\n"
    "entry { background-color: #374151; color: white; border: 1px solid #4b5563; border-radius: 6px; padding: 8px; }\n"
    "progressbar trough { background-color: #374151; border: none; border-radius: 9999px; min-height: 12px; }\n"
    "progressbar progress { background-color: #3b82f6; border-radius: 9999px; }\n"
    "treeview { background-color: #111827; color: #f3f4f6; border: 1px solid #374151; border-radius: 6px; }\n"
    "treeview header { background-color: #1f2937; color: #9ca3af; font-weight: bold; border-bottom: 2px solid #374151; }\n"
    "label.header { font-size: 18px; font-weight: 800; color: #3b82f6; margin-bottom: 8px; }\n"
    "label.status { font-size: 13px; color: #9ca3af; }\n"
    "checkbutton { color: #f3f4f6; }\n";

// Global operation state
static volatile int g_cancel_flag = 0;
static GtkWidget *g_start_buttons[3] = {NULL, NULL, NULL};
static GtkWidget *g_cancel_buttons[3] = {NULL, NULL, NULL};
static int g_active_tab = -1; // which tab has a running operation, -1 if none

// Forensic context struct to share UI pointers with thread
typedef struct {
    GtkWidget *progress_bar;
    GtkWidget *status_label;
    GtkListStore *list_store;
} ForensicContext;

// Structures for GUI Idle callbacks
typedef struct {
    GtkWidget *bar;
    GtkWidget *label;
    double fraction;
    char text[256];
} ProgressUpdate;

typedef struct {
    GtkListStore *store;
    char filename[256];
    long long offset;
    size_t size;
} CarveRowUpdate;

typedef struct {
    GtkListStore *store;
    char match_type[64];
    char text[256];
    long long offset;
} SearchRowUpdate;

// Thread args structs
typedef struct {
    char src[PATH_MAX];
    char dest[PATH_MAX];
    ForensicContext ctx;
} AcquireArgs;

typedef struct {
    char image[PATH_MAX];
    char output_dir[PATH_MAX];
    int jpeg;
    int png;
    int pdf;
    int zip;
    ForensicContext ctx;
} CarveArgs;

typedef struct {
    char image[PATH_MAX];
    char term[PATH_MAX];
    int keys;
    int emails;
    int passwords;
    ForensicContext ctx;
} SearchArgs;

// Idle update helpers
static gboolean update_progress_idle(gpointer data) {
    ProgressUpdate *up = (ProgressUpdate *)data;
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(up->bar), up->fraction);
    gtk_label_set_text(GTK_LABEL(up->label), up->text);
    free(up);
    return FALSE;
}

// Operation state management (called from worker threads via g_idle_add)
static gboolean set_operation_state_idle(gpointer data) {
    int running = GPOINTER_TO_INT(data);
    if (!running) {
        g_active_tab = -1;
        g_cancel_flag = 0;
    }
    for (int i = 0; i < 3; i++) {
        if (g_start_buttons[i])
            gtk_widget_set_sensitive(g_start_buttons[i], !running);
        if (g_cancel_buttons[i]) {
            if (running && g_active_tab == i)
                gtk_widget_show(g_cancel_buttons[i]);
            else
                gtk_widget_hide(g_cancel_buttons[i]);
        }
    }
    return FALSE;
}

static void begin_operation(int tab_index) {
    g_cancel_flag = 0;
    g_active_tab = tab_index;
    g_idle_add(set_operation_state_idle, GINT_TO_POINTER(1));
}

static void end_operation(void) {
    g_idle_add(set_operation_state_idle, GINT_TO_POINTER(0));
}

static gboolean add_carve_row_idle(gpointer data) {
    CarveRowUpdate *ru = (CarveRowUpdate *)data;
    GtkTreeIter iter;
    gtk_list_store_append(ru->store, &iter);
    gtk_list_store_set(ru->store, &iter,
                       0, ru->filename,
                       1, ru->offset,
                       2, (long long)ru->size,
                       -1);
    free(ru);
    return FALSE;
}

static gboolean add_search_row_idle(gpointer data) {
    SearchRowUpdate *ru = (SearchRowUpdate *)data;
    GtkTreeIter iter;
    gtk_list_store_append(ru->store, &iter);
    gtk_list_store_set(ru->store, &iter,
                       0, ru->match_type,
                       1, ru->text,
                       2, ru->offset,
                       -1);
    free(ru);
    return FALSE;
}

// Progress Callback Wrapper for Forensics Library
static void forward_progress(double fraction, const char *status_text, void *user_data) {
    ForensicContext *ctx = (ForensicContext *)user_data;
    ProgressUpdate *up = malloc(sizeof(ProgressUpdate));
    if (!up) return;
    up->bar = ctx->progress_bar;
    up->label = ctx->status_label;
    up->fraction = fraction;
    strncpy(up->text, status_text, sizeof(up->text) - 1);
    up->text[sizeof(up->text) - 1] = '\0';
    g_idle_add(update_progress_idle, up);
}

// Carve Callback Wrapper
static void forward_carve(const char *filename, long long offset, size_t size, void *user_data) {
    ForensicContext *ctx = (ForensicContext *)user_data;
    CarveRowUpdate *ru = malloc(sizeof(CarveRowUpdate));
    if (!ru) return;
    ru->store = ctx->list_store;
    strncpy(ru->filename, filename, sizeof(ru->filename) - 1);
    ru->filename[sizeof(ru->filename) - 1] = '\0';
    ru->offset = offset;
    ru->size = size;
    g_idle_add(add_carve_row_idle, ru);
}

// Search Callback Wrapper
static void forward_search(const char *match_type, const char *matched_text, long long offset, void *user_data) {
    ForensicContext *ctx = (ForensicContext *)user_data;
    SearchRowUpdate *ru = malloc(sizeof(SearchRowUpdate));
    if (!ru) return;
    ru->store = ctx->list_store;
    strncpy(ru->match_type, match_type, sizeof(ru->match_type) - 1);
    ru->match_type[sizeof(ru->match_type) - 1] = '\0';
    
    // Trim/clean search preview string
    size_t preview_len = strlen(matched_text);
    if (preview_len > 120) {
        strncpy(ru->text, matched_text, 117);
        ru->text[117] = '.';
        ru->text[118] = '.';
        ru->text[119] = '.';
        ru->text[120] = '\0';
    } else {
        strncpy(ru->text, matched_text, sizeof(ru->text) - 1);
        ru->text[sizeof(ru->text) - 1] = '\0';
    }
    
    ru->offset = offset;
    g_idle_add(add_search_row_idle, ru);
}

// Cancel button callback
static void on_cancel_operation(GtkWidget *btn, gpointer data) {
    (void)btn;
    (void)data;
    g_cancel_flag = 1;
}

// Worker Threads
static void *acquire_worker(void *arg) {
    AcquireArgs *args = (AcquireArgs *)arg;
    
    dump_partition(args->src, args->dest, forward_progress, &args->ctx, &g_cancel_flag);

    end_operation();
    free(args);
    return NULL;
}

static void *carve_worker(void *arg) {
    CarveArgs *args = (CarveArgs *)arg;

    carve_files(args->image, args->output_dir, args->jpeg, args->png, args->pdf, args->zip,
                forward_progress, forward_carve, &args->ctx, &g_cancel_flag);

    end_operation();
    free(args);
    return NULL;
}

static void *search_worker(void *arg) {
    SearchArgs *args = (SearchArgs *)arg;

    search_signatures(args->image, args->term, args->keys, args->emails, args->passwords,
                      forward_progress, forward_search, &args->ctx, &g_cancel_flag);

    end_operation();
    free(args);
    return NULL;
}

// GUI Actions
static void on_btn_browse_device(GtkWidget *btn, gpointer entry) {
    (void)btn;
    GtkWidget *dialog = gtk_file_chooser_dialog_new("Select Device or Partition Block File",
                                      NULL,
                                      GTK_FILE_CHOOSER_ACTION_OPEN,
                                      "_Cancel", GTK_RESPONSE_CANCEL,
                                      "_Open", GTK_RESPONSE_ACCEPT,
                                      NULL);
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        gtk_entry_set_text(GTK_ENTRY(entry), filename);
        g_free(filename);
    }
    gtk_widget_destroy(dialog);
}

static void on_btn_save_dump(GtkWidget *btn, gpointer entry) {
    (void)btn;
    GtkWidget *dialog = gtk_file_chooser_dialog_new("Specify Partition Dump Output File",
                                      NULL,
                                      GTK_FILE_CHOOSER_ACTION_SAVE,
                                      "_Cancel", GTK_RESPONSE_CANCEL,
                                      "_Save", GTK_RESPONSE_ACCEPT,
                                      NULL);
    gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(dialog), TRUE);
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        gtk_entry_set_text(GTK_ENTRY(entry), filename);
        g_free(filename);
    }
    gtk_widget_destroy(dialog);
}

static void on_btn_browse_file(GtkWidget *btn, gpointer entry) {
    (void)btn;
    GtkWidget *dialog = gtk_file_chooser_dialog_new("Select Forensic Dump File",
                                      NULL,
                                      GTK_FILE_CHOOSER_ACTION_OPEN,
                                      "_Cancel", GTK_RESPONSE_CANCEL,
                                      "_Open", GTK_RESPONSE_ACCEPT,
                                      NULL);
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        gtk_entry_set_text(GTK_ENTRY(entry), filename);
        g_free(filename);
    }
    gtk_widget_destroy(dialog);
}

static void on_btn_browse_dir(GtkWidget *btn, gpointer entry) {
    (void)btn;
    GtkWidget *dialog = gtk_file_chooser_dialog_new("Select Output Directory",
                                      NULL,
                                      GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER,
                                      "_Cancel", GTK_RESPONSE_CANCEL,
                                      "_Select", GTK_RESPONSE_ACCEPT,
                                      NULL);
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        gtk_entry_set_text(GTK_ENTRY(entry), filename);
        g_free(filename);
    }
    gtk_widget_destroy(dialog);
}

static void on_start_acquire(GtkWidget *btn, gpointer data) {
    (void)btn;
    GtkWidget **widgets = (GtkWidget **)data;
    GtkWidget *entry_src = widgets[0];
    GtkWidget *entry_dest = widgets[1];
    GtkWidget *progress_bar = widgets[2];
    GtkWidget *status_label = widgets[3];

    const char *src = gtk_entry_get_text(GTK_ENTRY(entry_src));
    const char *dest = gtk_entry_get_text(GTK_ENTRY(entry_dest));

    if (strlen(src) == 0 || strlen(dest) == 0) {
        gtk_label_set_text(GTK_LABEL(status_label), "Error: Source and Destination must be defined!");
        return;
    }

    if (g_active_tab >= 0) {
        gtk_label_set_text(GTK_LABEL(status_label), "Error: Another operation is already running!");
        return;
    }

    begin_operation(0);
    gtk_label_set_text(GTK_LABEL(status_label), "Acquiring dump in background...");
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(progress_bar), 0.0);

    AcquireArgs *args = malloc(sizeof(AcquireArgs));
    if (!args) {
        end_operation();
        gtk_label_set_text(GTK_LABEL(status_label), "Error: Memory allocation failed!");
        return;
    }
    strncpy(args->src, src, sizeof(args->src) - 1);
    args->src[sizeof(args->src) - 1] = '\0';
    strncpy(args->dest, dest, sizeof(args->dest) - 1);
    args->dest[sizeof(args->dest) - 1] = '\0';
    args->ctx.progress_bar = progress_bar;
    args->ctx.status_label = status_label;
    args->ctx.list_store = NULL;

    pthread_t thread;
    int ret = pthread_create(&thread, NULL, acquire_worker, args);
    if (ret != 0) {
        end_operation();
        free(args);
        gtk_label_set_text(GTK_LABEL(status_label), "Error: Failed to create worker thread!");
        return;
    }
    pthread_detach(thread);
}

static void on_start_carve(GtkWidget *btn, gpointer data) {
    (void)btn;
    GtkWidget **widgets = (GtkWidget **)data;
    GtkWidget *entry_img = widgets[0];
    GtkWidget *entry_dir = widgets[1];
    GtkWidget *chk_jpg = widgets[2];
    GtkWidget *chk_png = widgets[3];
    GtkWidget *chk_pdf = widgets[4];
    GtkWidget *chk_zip = widgets[5];
    GtkWidget *progress_bar = widgets[6];
    GtkWidget *status_label = widgets[7];
    GtkWidget *tree_view = widgets[8];

    const char *image = gtk_entry_get_text(GTK_ENTRY(entry_img));
    const char *out_dir = gtk_entry_get_text(GTK_ENTRY(entry_dir));

    if (strlen(image) == 0 || strlen(out_dir) == 0) {
        gtk_label_set_text(GTK_LABEL(status_label), "Error: Dump file and Output directory must be defined!");
        return;
    }

    if (g_active_tab >= 0) {
        gtk_label_set_text(GTK_LABEL(status_label), "Error: Another operation is already running!");
        return;
    }

    GtkListStore *store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(tree_view)));
    gtk_list_store_clear(store);

    begin_operation(1);
    gtk_label_set_text(GTK_LABEL(status_label), "Carving files in background...");
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(progress_bar), 0.0);

    CarveArgs *args = malloc(sizeof(CarveArgs));
    if (!args) {
        end_operation();
        gtk_label_set_text(GTK_LABEL(status_label), "Error: Memory allocation failed!");
        return;
    }
    strncpy(args->image, image, sizeof(args->image) - 1);
    args->image[sizeof(args->image) - 1] = '\0';
    strncpy(args->output_dir, out_dir, sizeof(args->output_dir) - 1);
    args->output_dir[sizeof(args->output_dir) - 1] = '\0';
    args->jpeg = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(chk_jpg));
    args->png = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(chk_png));
    args->pdf = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(chk_pdf));
    args->zip = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(chk_zip));
    args->ctx.progress_bar = progress_bar;
    args->ctx.status_label = status_label;
    args->ctx.list_store = store;

    pthread_t thread;
    int ret = pthread_create(&thread, NULL, carve_worker, args);
    if (ret != 0) {
        end_operation();
        free(args);
        gtk_label_set_text(GTK_LABEL(status_label), "Error: Failed to create worker thread!");
        return;
    }
    pthread_detach(thread);
}

static void on_start_search(GtkWidget *btn, gpointer data) {
    (void)btn;
    GtkWidget **widgets = (GtkWidget **)data;
    GtkWidget *entry_img = widgets[0];
    GtkWidget *entry_term = widgets[1];
    GtkWidget *chk_keys = widgets[2];
    GtkWidget *chk_emails = widgets[3];
    GtkWidget *chk_passwords = widgets[4];
    GtkWidget *progress_bar = widgets[5];
    GtkWidget *status_label = widgets[6];
    GtkWidget *tree_view = widgets[7];

    const char *image = gtk_entry_get_text(GTK_ENTRY(entry_img));
    const char *term = gtk_entry_get_text(GTK_ENTRY(entry_term));

    if (strlen(image) == 0) {
        gtk_label_set_text(GTK_LABEL(status_label), "Error: Forensic Dump file must be defined!");
        return;
    }

    if (g_active_tab >= 0) {
        gtk_label_set_text(GTK_LABEL(status_label), "Error: Another operation is already running!");
        return;
    }

    GtkListStore *store = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(tree_view)));
    gtk_list_store_clear(store);

    begin_operation(2);
    gtk_label_set_text(GTK_LABEL(status_label), "Searching dump file in background...");
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(progress_bar), 0.0);

    SearchArgs *args = malloc(sizeof(SearchArgs));
    if (!args) {
        end_operation();
        gtk_label_set_text(GTK_LABEL(status_label), "Error: Memory allocation failed!");
        return;
    }
    strncpy(args->image, image, sizeof(args->image) - 1);
    args->image[sizeof(args->image) - 1] = '\0';
    strncpy(args->term, term, sizeof(args->term) - 1);
    args->term[sizeof(args->term) - 1] = '\0';
    args->keys = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(chk_keys));
    args->emails = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(chk_emails));
    args->passwords = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(chk_passwords));
    args->ctx.progress_bar = progress_bar;
    args->ctx.status_label = status_label;
    args->ctx.list_store = store;

    pthread_t thread;
    int ret = pthread_create(&thread, NULL, search_worker, args);
    if (ret != 0) {
        end_operation();
        free(args);
        gtk_label_set_text(GTK_LABEL(status_label), "Error: Failed to create worker thread!");
        return;
    }
    pthread_detach(thread);
}

int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);

    // Apply custom styling via CSS Provider
    GtkCssProvider *css_provider = gtk_css_provider_new();
    gtk_css_provider_load_from_data(css_provider, custom_css, -1, NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
                                              GTK_STYLE_PROVIDER(css_provider),
                                              GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Forensic Dump v2.0.2");
    gtk_window_set_default_size(GTK_WINDOW(window), 850, 600);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    // Set taskbar and window icon
    // Check local location first, fall back to global path
    if (!gtk_window_set_icon_from_file(GTK_WINDOW(window), "./resources/forensic-tool.png", NULL)) {
        gtk_window_set_icon_from_file(GTK_WINDOW(window), "/usr/share/icons/hicolor/scalable/apps/forensic-tool.png", NULL);
    }

    GtkWidget *notebook = gtk_notebook_new();
    gtk_container_set_border_width(GTK_CONTAINER(notebook), 10);

    // ==========================================
    // TAB 1: ACQUIRE (DUMP PARTITION)
    // ==========================================
    GtkWidget *tab1_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_container_set_border_width(GTK_CONTAINER(tab1_vbox), 20);

    GtkWidget *lbl_acquire_title = gtk_label_new("Acquire Partition Dump File");
    gtk_widget_set_name(lbl_acquire_title, "header_lbl");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl_acquire_title), "header");
    gtk_label_set_xalign(GTK_LABEL(lbl_acquire_title), 0.0);
    gtk_box_pack_start(GTK_BOX(tab1_vbox), lbl_acquire_title, FALSE, FALSE, 0);

    // Grid for inputs
    GtkWidget *grid1 = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid1), 10);
    gtk_grid_set_column_spacing(GTK_GRID(grid1), 10);

    GtkWidget *lbl_src = gtk_label_new("Source Device / File:");
    gtk_label_set_xalign(GTK_LABEL(lbl_src), 0.0);
    GtkWidget *entry_src = gtk_entry_new();
    gtk_widget_set_hexpand(entry_src, TRUE);
    GtkWidget *btn_browse_src = gtk_button_new_with_label("Browse / Dev");
    g_signal_connect(btn_browse_src, "clicked", G_CALLBACK(on_btn_browse_device), entry_src);

    gtk_grid_attach(GTK_GRID(grid1), lbl_src, 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid1), entry_src, 1, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid1), btn_browse_src, 2, 0, 1, 1);

    GtkWidget *lbl_dest = gtk_label_new("Destination Dump (.img):");
    gtk_label_set_xalign(GTK_LABEL(lbl_dest), 0.0);
    GtkWidget *entry_dest = gtk_entry_new();
    gtk_widget_set_hexpand(entry_dest, TRUE);
    GtkWidget *btn_browse_dest = gtk_button_new_with_label("Select Destination");
    g_signal_connect(btn_browse_dest, "clicked", G_CALLBACK(on_btn_save_dump), entry_dest);

    gtk_grid_attach(GTK_GRID(grid1), lbl_dest, 0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid1), entry_dest, 1, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid1), btn_browse_dest, 2, 1, 1, 1);

    gtk_box_pack_start(GTK_BOX(tab1_vbox), grid1, FALSE, FALSE, 0);

    // Progress
    GtkWidget *prog_acquire = gtk_progress_bar_new();
    gtk_progress_bar_set_show_text(GTK_PROGRESS_BAR(prog_acquire), TRUE);
    GtkWidget *lbl_status_acquire = gtk_label_new("Ready.");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl_status_acquire), "status");
    gtk_label_set_xalign(GTK_LABEL(lbl_status_acquire), 0.0);

    gtk_box_pack_start(GTK_BOX(tab1_vbox), prog_acquire, FALSE, FALSE, 4);
    gtk_box_pack_start(GTK_BOX(tab1_vbox), lbl_status_acquire, FALSE, FALSE, 4);

    // Buttons box for start + cancel
    GtkWidget *btn_start_acquire = gtk_button_new_with_label("Start Acquisition");
    gtk_style_context_add_class(gtk_widget_get_style_context(btn_start_acquire), "suggested-action");

    GtkWidget *btn_cancel_acquire = gtk_button_new_with_label("Cancel");
    gtk_style_context_add_class(gtk_widget_get_style_context(btn_cancel_acquire), "destructive-action");
    gtk_widget_set_no_show_all(btn_cancel_acquire, TRUE);
    g_signal_connect(btn_cancel_acquire, "clicked", G_CALLBACK(on_cancel_operation), NULL);

    gtk_box_pack_end(GTK_BOX(tab1_vbox), btn_cancel_acquire, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(tab1_vbox), btn_start_acquire, FALSE, FALSE, 0);

    g_start_buttons[0] = btn_start_acquire;
    g_cancel_buttons[0] = btn_cancel_acquire;

    static GtkWidget *acquire_widgets[4];
    acquire_widgets[0] = entry_src;
    acquire_widgets[1] = entry_dest;
    acquire_widgets[2] = prog_acquire;
    acquire_widgets[3] = lbl_status_acquire;
    g_signal_connect(btn_start_acquire, "clicked", G_CALLBACK(on_start_acquire), acquire_widgets);

    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), tab1_vbox, gtk_label_new("Acquire (Dump)"));

    // ==========================================
    // TAB 2: CARVE (EXTRACT FILES)
    // ==========================================
    GtkWidget *tab2_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(tab2_vbox), 20);

    GtkWidget *lbl_carve_title = gtk_label_new("File Carving Tool");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl_carve_title), "header");
    gtk_label_set_xalign(GTK_LABEL(lbl_carve_title), 0.0);
    gtk_box_pack_start(GTK_BOX(tab2_vbox), lbl_carve_title, FALSE, FALSE, 0);

    // Target image
    GtkWidget *grid2 = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid2), 8);
    gtk_grid_set_column_spacing(GTK_GRID(grid2), 10);

    GtkWidget *lbl_img_carve = gtk_label_new("Dump Image File:");
    gtk_label_set_xalign(GTK_LABEL(lbl_img_carve), 0.0);
    GtkWidget *entry_img_carve = gtk_entry_new();
    gtk_widget_set_hexpand(entry_img_carve, TRUE);
    GtkWidget *btn_browse_img_carve = gtk_button_new_with_label("Select Dump");
    g_signal_connect(btn_browse_img_carve, "clicked", G_CALLBACK(on_btn_browse_file), entry_img_carve);

    gtk_grid_attach(GTK_GRID(grid2), lbl_img_carve, 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid2), entry_img_carve, 1, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid2), btn_browse_img_carve, 2, 0, 1, 1);

    GtkWidget *lbl_out_carve = gtk_label_new("Output Folder:");
    gtk_label_set_xalign(GTK_LABEL(lbl_out_carve), 0.0);
    GtkWidget *entry_out_carve = gtk_entry_new();
    gtk_widget_set_hexpand(entry_out_carve, TRUE);
    GtkWidget *btn_browse_out_carve = gtk_button_new_with_label("Select Output Folder");
    g_signal_connect(btn_browse_out_carve, "clicked", G_CALLBACK(on_btn_browse_dir), entry_out_carve);

    gtk_grid_attach(GTK_GRID(grid2), lbl_out_carve, 0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid2), entry_out_carve, 1, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid2), btn_browse_out_carve, 2, 1, 1, 1);

    gtk_box_pack_start(GTK_BOX(tab2_vbox), grid2, FALSE, FALSE, 0);

    // Checkboxes
    GtkWidget *hbox_chks = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 20);
    GtkWidget *chk_jpg = gtk_check_button_new_with_label("Carve JPEG (.jpg)");
    GtkWidget *chk_png = gtk_check_button_new_with_label("Carve PNG (.png)");
    GtkWidget *chk_pdf = gtk_check_button_new_with_label("Carve PDF (.pdf)");
    GtkWidget *chk_zip = gtk_check_button_new_with_label("Carve ZIP (.zip)");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(chk_jpg), TRUE);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(chk_png), TRUE);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(chk_pdf), TRUE);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(chk_zip), TRUE);

    gtk_box_pack_start(GTK_BOX(hbox_chks), chk_jpg, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hbox_chks), chk_png, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hbox_chks), chk_pdf, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hbox_chks), chk_zip, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(tab2_vbox), hbox_chks, FALSE, FALSE, 4);

    // Results Tree View
    GtkListStore *store_carve = gtk_list_store_new(3, G_TYPE_STRING, G_TYPE_INT64, G_TYPE_INT64);
    GtkWidget *tree_carve = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store_carve));
    g_object_unref(store_carve);

    GtkCellRenderer *renderer = gtk_cell_renderer_text_new();
    gtk_tree_view_append_column(GTK_TREE_VIEW(tree_carve),
        gtk_tree_view_column_new_with_attributes("Filename", renderer, "text", 0, NULL));
    gtk_tree_view_append_column(GTK_TREE_VIEW(tree_carve),
        gtk_tree_view_column_new_with_attributes("Offset (Bytes)", renderer, "text", 1, NULL));
    gtk_tree_view_append_column(GTK_TREE_VIEW(tree_carve),
        gtk_tree_view_column_new_with_attributes("Size (Bytes)", renderer, "text", 2, NULL));

    GtkWidget *scroll_carve = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll_carve), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(scroll_carve), tree_carve);
    gtk_box_pack_start(GTK_BOX(tab2_vbox), scroll_carve, TRUE, TRUE, 0);

    // Progress
    GtkWidget *prog_carve = gtk_progress_bar_new();
    gtk_progress_bar_set_show_text(GTK_PROGRESS_BAR(prog_carve), TRUE);
    GtkWidget *lbl_status_carve = gtk_label_new("Ready.");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl_status_carve), "status");
    gtk_label_set_xalign(GTK_LABEL(lbl_status_carve), 0.0);

    gtk_box_pack_start(GTK_BOX(tab2_vbox), prog_carve, FALSE, FALSE, 2);
    gtk_box_pack_start(GTK_BOX(tab2_vbox), lbl_status_carve, FALSE, FALSE, 2);

    GtkWidget *btn_start_carve = gtk_button_new_with_label("Start File Carving");
    gtk_style_context_add_class(gtk_widget_get_style_context(btn_start_carve), "suggested-action");

    GtkWidget *btn_cancel_carve = gtk_button_new_with_label("Cancel");
    gtk_style_context_add_class(gtk_widget_get_style_context(btn_cancel_carve), "destructive-action");
    gtk_widget_set_no_show_all(btn_cancel_carve, TRUE);
    g_signal_connect(btn_cancel_carve, "clicked", G_CALLBACK(on_cancel_operation), NULL);

    gtk_box_pack_end(GTK_BOX(tab2_vbox), btn_cancel_carve, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(tab2_vbox), btn_start_carve, FALSE, FALSE, 0);

    g_start_buttons[1] = btn_start_carve;
    g_cancel_buttons[1] = btn_cancel_carve;

    static GtkWidget *carve_widgets[9];
    carve_widgets[0] = entry_img_carve;
    carve_widgets[1] = entry_out_carve;
    carve_widgets[2] = chk_jpg;
    carve_widgets[3] = chk_png;
    carve_widgets[4] = chk_pdf;
    carve_widgets[5] = chk_zip;
    carve_widgets[6] = prog_carve;
    carve_widgets[7] = lbl_status_carve;
    carve_widgets[8] = tree_carve;
    g_signal_connect(btn_start_carve, "clicked", G_CALLBACK(on_start_carve), carve_widgets);

    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), tab2_vbox, gtk_label_new("File Carving"));

    // ==========================================
    // TAB 3: SIGNATURE SEARCH (KEYS, PASSWORDS, ETC)
    // ==========================================
    GtkWidget *tab3_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(tab3_vbox), 20);

    GtkWidget *lbl_search_title = gtk_label_new("Credential & Signature Search");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl_search_title), "header");
    gtk_label_set_xalign(GTK_LABEL(lbl_search_title), 0.0);
    gtk_box_pack_start(GTK_BOX(tab3_vbox), lbl_search_title, FALSE, FALSE, 0);

    // Target image + term
    GtkWidget *grid3 = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid3), 8);
    gtk_grid_set_column_spacing(GTK_GRID(grid3), 10);

    GtkWidget *lbl_img_search = gtk_label_new("Dump Image File:");
    gtk_label_set_xalign(GTK_LABEL(lbl_img_search), 0.0);
    GtkWidget *entry_img_search = gtk_entry_new();
    gtk_widget_set_hexpand(entry_img_search, TRUE);
    GtkWidget *btn_browse_img_search = gtk_button_new_with_label("Select Dump");
    g_signal_connect(btn_browse_img_search, "clicked", G_CALLBACK(on_btn_browse_file), entry_img_search);

    gtk_grid_attach(GTK_GRID(grid3), lbl_img_search, 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid3), entry_img_search, 1, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid3), btn_browse_img_search, 2, 0, 1, 1);

    GtkWidget *lbl_term = gtk_label_new("Custom Term Search:");
    gtk_label_set_xalign(GTK_LABEL(lbl_term), 0.0);
    GtkWidget *entry_term = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry_term), "e.g. flag, username, confidential");

    gtk_grid_attach(GTK_GRID(grid3), lbl_term, 0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid3), entry_term, 1, 1, 2, 1);

    gtk_box_pack_start(GTK_BOX(tab3_vbox), grid3, FALSE, FALSE, 0);

    // Checkboxes
    GtkWidget *hbox_chks_search = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 20);
    GtkWidget *chk_keys = gtk_check_button_new_with_label("Private Keys (PEM)");
    GtkWidget *chk_emails = gtk_check_button_new_with_label("Email Addresses");
    GtkWidget *chk_passwords = gtk_check_button_new_with_label("Passwords / Credentials");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(chk_keys), TRUE);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(chk_emails), TRUE);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(chk_passwords), TRUE);

    gtk_box_pack_start(GTK_BOX(hbox_chks_search), chk_keys, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hbox_chks_search), chk_emails, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hbox_chks_search), chk_passwords, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(tab3_vbox), hbox_chks_search, FALSE, FALSE, 4);

    // Results Tree View
    GtkListStore *store_search = gtk_list_store_new(3, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_INT64);
    GtkWidget *tree_search = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store_search));
    g_object_unref(store_search);

    GtkCellRenderer *renderer_s = gtk_cell_renderer_text_new();
    gtk_tree_view_append_column(GTK_TREE_VIEW(tree_search),
        gtk_tree_view_column_new_with_attributes("Match Type", renderer_s, "text", 0, NULL));
    gtk_tree_view_append_column(GTK_TREE_VIEW(tree_search),
        gtk_tree_view_column_new_with_attributes("Matched Text Preview", renderer_s, "text", 1, NULL));
    gtk_tree_view_append_column(GTK_TREE_VIEW(tree_search),
        gtk_tree_view_column_new_with_attributes("Offset (Bytes)", renderer_s, "text", 2, NULL));

    GtkWidget *scroll_search = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll_search), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(scroll_search), tree_search);
    gtk_box_pack_start(GTK_BOX(tab3_vbox), scroll_search, TRUE, TRUE, 0);

    // Progress
    GtkWidget *prog_search = gtk_progress_bar_new();
    gtk_progress_bar_set_show_text(GTK_PROGRESS_BAR(prog_search), TRUE);
    GtkWidget *lbl_status_search = gtk_label_new("Ready.");
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl_status_search), "status");
    gtk_label_set_xalign(GTK_LABEL(lbl_status_search), 0.0);

    gtk_box_pack_start(GTK_BOX(tab3_vbox), prog_search, FALSE, FALSE, 2);
    gtk_box_pack_start(GTK_BOX(tab3_vbox), lbl_status_search, FALSE, FALSE, 2);

    GtkWidget *btn_start_search = gtk_button_new_with_label("Start Search");
    gtk_style_context_add_class(gtk_widget_get_style_context(btn_start_search), "suggested-action");

    GtkWidget *btn_cancel_search = gtk_button_new_with_label("Cancel");
    gtk_style_context_add_class(gtk_widget_get_style_context(btn_cancel_search), "destructive-action");
    gtk_widget_set_no_show_all(btn_cancel_search, TRUE);
    g_signal_connect(btn_cancel_search, "clicked", G_CALLBACK(on_cancel_operation), NULL);

    gtk_box_pack_end(GTK_BOX(tab3_vbox), btn_cancel_search, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(tab3_vbox), btn_start_search, FALSE, FALSE, 0);

    g_start_buttons[2] = btn_start_search;
    g_cancel_buttons[2] = btn_cancel_search;

    static GtkWidget *search_widgets[8];
    search_widgets[0] = entry_img_search;
    search_widgets[1] = entry_term;
    search_widgets[2] = chk_keys;
    search_widgets[3] = chk_emails;
    search_widgets[4] = chk_passwords;
    search_widgets[5] = prog_search;
    search_widgets[6] = lbl_status_search;
    search_widgets[7] = tree_search;
    g_signal_connect(btn_start_search, "clicked", G_CALLBACK(on_start_search), search_widgets);

    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), tab3_vbox, gtk_label_new("Credential / Key Search"));

    // Main layout pack
    gtk_container_add(GTK_CONTAINER(window), notebook);
    gtk_widget_show_all(window);

    gtk_main();

    // css_provider is still referenced by the screen's style context;
    // no need to manually unref here as the process is exiting.
    return 0;
}
