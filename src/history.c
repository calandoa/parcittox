/* Copyright (C) 2007-2008 by Xyhthyx <xyhthyx@gmail.com>
 *
 * This file is part of Parcellite.
 *
 * Parcellite is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Parcellite is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.	If not, see <http://www.gnu.org/licenses/>.
 */

#include <glib/gprintf.h>

#include "parcellite.h"

/**This is now a gslist of	 */
GList* history_list = NULL;
static gint dbg=0;
/**todo:
handle parcellite history magic:
if it does not exist, then we assume original format, and convert.
	Need to provide a menu item that allows user to convert back to old?
	or just provide manual instructions to convert back (i.e. dd skip)?

	*/
#define HISTORY_MAGIC_SIZE 32
#define HISTORY_VERSION		 1 /**index (-1) into array below	*/
static gchar* history_magics[]={
	"1.0" PARCELLITE_PROG_NAME "HistoryFile",
	NULL,
};

/***************************************************************************/
/** Pass in the text via the struct. We assume len is correct, and BYTE based,
not character.
\n\b Arguments:
\n\b Returns:	length of resulting string.
****************************************************************************/
glong validate_utf8_text(gchar *text)
{
	gchar *valid;
	if (g_utf8_validate(text, -1, (const gchar **)&valid) == FALSE) {
		*valid = '\0';
		fprintf(stderr, "******************* Truncating invalid utf8 text entry: <%s>", text);
	}
	return valid - text;
}

void validate_hist(int n)
{
	GList* element;

	/* Write each element to a binary file */
	for (element = history_list; element; element = element->next) {
		struct history_item *c = (struct history_item *)element->data;

		glong len = validate_utf8_text(c->text);
		if (len != c->len)
			fprintf(stderr, "***** %d ***** HIST ERROR %ld / %d <%s>\n", n, len, c->len, c->text);
	}
}
/***************************************************************************/
/** Read the old history file and covert to the new format.
\n\b Arguments:
\n\b Returns:
****************************************************************************/
void read_history_old (void)
{
	/* Build file path */
	gchar* history_path = g_build_filename(g_get_user_data_dir(), HISTORY_FILE, NULL);

	/* Open the file for reading */
	FILE* history_file = fopen(history_path, "rb");
	g_free(history_path);
	/* Check that it opened and begin read */
	if (history_file)	 {
		/* Read the size of the first item */
		gint size=1;

		/* Continue reading until size is 0 */
		while (size)	 {
			struct history_item *c;
			if (fread(&size, 4, 1, history_file) != 1){
				size = 0;
				break;
			} else if( 0 == size )
				break;
			/* Malloc according to the size of the item */
			c = (struct history_item *)g_malloc0(sizeof(struct history_item) + size + 1);
			c->type = CLIP_TYPE_TEXT;
			c->len = size;
			/* Read item and add ending character */
			if (fread(c->text, size, 1, history_file) !=1){
				g_printf("Error reading history file entry \n");
			} else {
				c->text[size] = 0;
				c->len = validate_utf8_text(c->text);
				/* Prepend item and read next size */
				history_list = g_list_prepend(history_list, c);
			}
		}
		/* Close file and reverse the history to normal */
		fclose(history_file);
		history_list = g_list_reverse(history_list);
	}
}

/* Saves history to ~/.local/share/parcellite/history */
void save_history_old(void)
{
	/* Check that the directory is available */
	check_dirs();
	/* Build file path */
	gchar* history_path = g_build_filename(g_get_user_data_dir(), HISTORY_FILE, NULL);
	/* Open the file for writing */
	FILE* history_file = fopen(history_path, "wb");
	g_free(history_path);
	/* Check that it opened and begin write */
	if (history_file)	{
		GList* element;
		/* Write each element to a binary file */
		for (element = history_list; element != NULL; element = element->next) {
			/* Create new GString from element data, write its length (size)
			 * to file followed by the element data itself
			 */
			GString* item = g_string_new((gchar*)element->data);
			fwrite(&(item->len), 4, 1, history_file);
			fputs(item->str, history_file);
			g_string_free(item, TRUE);
		}
		/* Write 0 to indicate end of file */
		gint end = 0;
		fwrite(&end, 4, 1, history_file);
		fclose(history_file);
	}
}

/***************************************************************************/
/** .
\n\b Arguments:
magic is what we are looking for, fmagic iw what we read from the file.
\n\b Returns: history matched on match, -1 on erro, 0 if not found
****************************************************************************/
int check_magic(gchar *fmagic)
{
	int i;
	for (i = 0; history_magics[i]; ++i)
		if (!strncmp(history_magics[i], fmagic, HISTORY_MAGIC_SIZE))
			return i + 1;
	return 0;
}

/***************************************************************************/
/** Reads history from ~/.local/share/parcellite/history .
Current scheme is to have the total zize of element followed by the type, then the data
\n\b Arguments:
\n\b Returns:
****************************************************************************/
void read_history (void)
{
	/* Build file path */
	gchar* history_path = g_build_filename(g_get_user_data_dir(), HISTORY_FILE, NULL);
	gchar *magic = g_malloc0(HISTORY_MAGIC_SIZE + 2);
	/*g_printf("History file '%s'",history_path); */
	/* Open the file for reading */
	FILE* history_file = fopen(history_path, "rb");
	g_free(history_path);
	/* Check that it opened and begin read */
	if (history_file)	{
		/* Read the magic*/
		if (fread(magic, HISTORY_MAGIC_SIZE, 1, history_file) != 1){
			g_printf("No magic! Assume no history.\n");
			goto error;
		}

		if (HISTORY_VERSION != check_magic(magic)) {
			g_printf("Assuming old history style. Read and convert.\n");
			/*g_printf("TODO! History version not matching!!Discarding history.\n"); */
			read_history_old();
			goto error;
		}

		if(dbg)
			g_printf("History Magic OK. Reading\n");

		/* Continue reading until size is 0 */
		for (;;) {
			guint32 size, end;
			struct history_item *c;
			if (fread(&size, sizeof(guint32), 1, history_file) != 1 || size == 0)
				break;

			/* Malloc according to the size of the item */
			c = (struct history_item *) g_malloc0(sizeof(struct history_item) + size + 1);
			if (c == NULL)
				break;

			size = fread(c, 1, size, history_file);

			/* We must read a full history_item struct at least. Truncated data is OK */
			if (size < sizeof(struct history_item)) {
				g_printf("history_read: truncated struct!");
				g_free(c);
				break;
			}

			/* Truncate to the first NUL or invalid char */
			c->len = validate_utf8_text(c->text);
			history_list = g_list_append(history_list, c);

			// g_printf("history item: %d %d %x <%s>", c->len, c->type, c->flags, c->text);
		}
	error:
		g_free(magic);
		fclose(history_file);
	}

	if(dbg)
		g_printf("History read done\n");
}
/**	NOTES:
	gint width, height, rowstride, n_channels,bits_per_sample ;
	guchar *pixels;

	n_channels = gdk_pixbuf_get_n_channels (pixbuf);

	g_assert (gdk_pixbuf_get_colorspace (pixbuf) == GDK_COLORSPACE_RGB);
	bits_per_sample = gdk_pixbuf_get_bits_per_sample (pixbuf);

	width = gdk_pixbuf_get_width (pixbuf);
	height = gdk_pixbuf_get_height (pixbuf);

	rowstride = gdk_pixbuf_get_rowstride (pixbuf);
	pixels = gdk_pixbuf_get_pixels (pixbuf);

len of pixbuf = rowstride*(height-1)+width * ((n_channels * bits_per_sample + 7) / 8)

last row of pixbuf = width * ((n_channels * bits_per_sample + 7) / 8)
*/
/* Saves history to ~/.local/share/parcellite/history */

/***************************************************************************/
/** write total len, then write type, then write data.
\n\b Arguments:
\n\b Returns:
****************************************************************************/
void save_history(void)
{
	/* Check that the directory is available */
	check_dirs();
	/* Build file path */
	gchar* history_path = g_build_filename(g_get_user_data_dir(), HISTORY_FILE, NULL);
	/* Open the file for writing */
	FILE* history_file = fopen(history_path, "wb");
	g_free(history_path);

	/* Check that it opened and begin write */
	if (history_file) {
		GList* element;

		if (fwrite(history_magics[HISTORY_VERSION-1], HISTORY_MAGIC_SIZE, 1, history_file) != 1)
			goto error;

		/* Write each element to a binary file */
		for (element = history_list; element; element = element->next) {
			struct history_item *c = (struct history_item *)element->data;
			gint32 len = sizeof(struct history_item) + c->len;
			fwrite(&len, sizeof(guint32), 1, history_file);
			fwrite(c, sizeof(struct history_item), 1, history_file);
			fwrite(c->text, c->len, 1, history_file);
		}
		/* Write 0 as truncated history_item to indicate end of file */
		gint end = 0;
		fwrite(&end, 4, 1, history_file);

	error:
		fclose(history_file);
	}
}

/***************************************************************************/
/** .
\n\b Arguments:
\n\b Returns:
****************************************************************************/
struct history_item *new_clip_item(gint type, void *data)
{
	g_assert(type == CLIP_TYPE_TEXT);
	int len = validate_utf8_text(data);
	struct history_item *c = g_malloc0(sizeof(struct history_item) + len + 1);
	if (c == NULL) {
		printf("Hit NULL for malloc of history_item!\n");
		return NULL;
	}

	c->type = type;
	memcpy(c->text, data, len);
	c->len = len;

	return c;
}
/***************************************************************************/
/**	checks to see if text is already in history. Also is a find text
\n\b Arguments: if mode is 1, delete it too.
\n\b Returns: -1 if not found, or nth element.
****************************************************************************/
gint is_duplicate(gchar* item, int mode, gint *flags)
{
	GList* element;
	gint i;
	if(NULL ==item)
		return -1;
	/* Go through each element compare each */
	for (i=0,element = history_list; element != NULL; element = element->next,++i) {
		struct history_item *c;
		c=(struct history_item *)element->data;
		if (CLIP_TYPE_TEXT == c->type){
			if (g_strcmp0((gchar*)c->text, item) == 0) {
				if (mode){
					if(NULL != flags && (CLIP_TYPE_PERSISTENT&c->flags)){
						*flags = c->flags;
					}
					/*g_printf("Freeing 0x%02X '%s'\n",c->flags,c->text);	*/
					g_free(element->data);
					history_list = g_list_delete_link(history_list, element);
				}
				return i;
				break;
			}
		}
	}
	return -1;
}
/***************************************************************************/
/**	Adds item to the end of history .
\n\b Arguments:
\n\b Returns:
****************************************************************************/
int append_item(gchar* item, int checkdup)
{
	gint flags = 0, node = -1;
	gint ret = FALSE;
	static GMutex hist_lock;

	if(NULL == item)
		return ret;

	g_mutex_lock(&hist_lock);

	/**delete if HIST_DEL flag is set.	*/
	if (checkdup & HIST_CHECKDUP){
		node = is_duplicate(item, checkdup & HIST_DEL, &flags);
		/*g_printf("isd done "); */
		if (node > -1) { /**found it	*/
			/*g_printf(" found\n"); */
			if (!(checkdup & HIST_DEL))
				goto unlock;
		}
	}

	struct history_item *c = new_clip_item(CLIP_TYPE_TEXT, item);
	if(c == NULL)
		goto unlock;

	if (node > -1 && (checkdup & HIST_KEEP_FLAGS) ){
		c->flags = flags;
		/*g_printf("Restoring 0x%02X '%s'\n",c->flags,c->text);	*/
	}

	/*g_printf("Append '%s'\n",item); */
	 /* Prepend new item */
	history_list = g_list_prepend(history_list, c);

	/* Shorten history if necessary */
	truncate_history();
	ret = TRUE;
unlock:
	g_mutex_unlock(&hist_lock);
	return ret;
}

/***************************************************************************/
/**	Deletes duplicate item in history . Orphaned function.
\n\b Arguments:
\n\b Returns:
****************************************************************************/
void delete_duplicate(gchar* item)
{
	GList* element;
	int p = get_pref_int32("persistent_history");
	/* Go through each element compare each */
	for (element = history_list; element != NULL; element = element->next) {
		struct history_item *c;
		c=(struct history_item *)element->data;
		if( (!p || !(CLIP_TYPE_PERSISTENT&c->flags)) && CLIP_TYPE_TEXT == c->type){
			if (g_strcmp0((gchar*)c->text, item) == 0) {
				g_printf("del dup '%s'\n",c->text);
				g_free(element->data);
				history_list = g_list_delete_link(history_list, element);
				break;
			}
		}
	}
}

/***************************************************************************/
/**	Truncates history to history_limit items, while preserving persistent
		data, if specified by the user. FIXME: This may not shorten the history
\n\b Arguments:
\n\b Returns:
****************************************************************************/
void truncate_history(void)
{
	int p = get_pref_int32("persistent_history");
	if (history_list)	{
		guint ll = g_list_length(history_list);
		guint lim = get_pref_int32("history_limit");
		if(ll > lim){ /* Shorten history if necessary */
			GList* last = g_list_last(history_list);
			while (last->prev && ll>lim)	 {
				struct history_item *c=(struct history_item *)last->data;
				last = last->prev;
				if(!p || !(c->flags&CLIP_TYPE_PERSISTENT)){
					history_list = g_list_remove(history_list,c);
					--ll;
				}
			}
		}

		/* Save changes */
		if (get_pref_int32("save_history"))
			save_history();
	}
}

/* Returns pointer to last item in history */
gpointer get_last_item(void)
{
	if (history_list)
	{
		if (history_list->data)
		{
			/* Return the last element */
			gpointer last_item = history_list->data;
			return last_item;
		}
		else
			return NULL;
	}
	else
		return NULL;
}


/***************************************************************************/
/** .
\n\b Arguments:
\n\b Returns:
****************************************************************************/
int save_history_as_text(gchar *path)
{
	FILE* fp = fopen(path, "w");
	/* Check that it opened and begin write */
	if (fp)	{
		gint i;
		GList* element;
		/* Write each element to	file */
		for (i=0,element = history_list; element != NULL; element = element->next) {
			struct history_item *c;
			c=(struct history_item *)element->data;
			if(c->flags & CLIP_TYPE_PERSISTENT)
				fprintf(fp,"PHIST_%04d %s\n",i,c->text);
			else
				fprintf(fp,"NHIST_%04d %s\n",i,c->text);
			++i;
		}
		fclose(fp);
	}

	g_printf("histpath='%s'\n",path);
}
/***************************************************************************/
/** Dialog to save the history file.
\n\b Arguments:
\n\b Returns:
****************************************************************************/
void history_save_as(GtkMenuItem *menu_item, gpointer user_data)
{
	GtkWidget *dialog;
	dialog = gtk_file_chooser_dialog_new ("Save History File",
							NULL,/**parent	*/
							GTK_FILE_CHOOSER_ACTION_SAVE,
							GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
							GTK_STOCK_SAVE, GTK_RESPONSE_ACCEPT,
							NULL);
	gtk_file_chooser_set_do_overwrite_confirmation (GTK_FILE_CHOOSER (dialog), TRUE);
/*	if (user_edited_a_new_document)	{ */
			gtk_file_chooser_set_current_folder (GTK_FILE_CHOOSER (dialog), g_get_home_dir());
			gtk_file_chooser_set_current_name (GTK_FILE_CHOOSER (dialog), PARCELLITE_PROG_NAME "_history.txt");
/**		}
	else
		gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (dialog), filename_for_existing_document);*/
	if (gtk_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_ACCEPT) {
			gchar *filename;
			filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog));
			save_history_as_text (filename);
			g_free (filename);
		}
	gtk_widget_destroy (dialog);
}

