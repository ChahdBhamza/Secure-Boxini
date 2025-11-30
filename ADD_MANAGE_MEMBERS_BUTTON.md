# How to Add the "Manage Members" Button to Dashboard

## Problem
The dashboard.html file needs a "Manage Members" button on folder cards, but automated editing keeps corrupting the file.

## Solution: Manual Edit

### Step 1: Open the File
Open `templates/dashboard.html` in your code editor

### Step 2: Find the Location
Search for this comment (around line 164):
```html
<!-- Delete Folder Button (Absolute positioned) -->
```

### Step 3: Replace Lines 164-173
Replace the entire delete button section (lines 164-173) with this code:

```html
            <!-- Folder Action Buttons -->
            <div class="absolute top-2 right-2 flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
              <!-- Manage Members Button -->
              <a href="{{ url_for('folder_members', folder_id=folder.folder_id) }}"
                class="p-1.5 text-slate-400 hover:text-blue-400 bg-slate-900/90 rounded transition-colors"
                title="Manage Members"
                onclick="event.stopPropagation();">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                    d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z">
                  </path>
                </svg>
              </a>
              
              <!-- Delete Folder Button -->
              <a href="{{ url_for('delete_folder', folder_id=folder.folder_id) }}"
                onclick="event.stopPropagation(); return confirm('Delete folder {{ folder.name }} and all its contents?')"
                class="p-1.5 text-slate-400 hover:text-red-400 bg-slate-900/90 rounded transition-colors"
                title="Delete Folder">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                    d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16">
                  </path>
                </svg>
              </a>
            </div>
```

### Step 4: Save and Test
1. Save the file
2. Refresh your browser
3. Hover over the "family" folder
4. You should see TWO icons appear:
   - **Person icon** (left) = Click to manage members
   - **Trash icon** (right) = Click to delete folder

## What This Does
- Adds a "Manage Members" button (person icon) next to the delete button
- Both buttons appear when you hover over a folder
- Clicking the person icon takes you to `/folder/<folder_id>/members` where you can:
  - Add users to the folder
  - Assign roles (Admin/Member/Viewer)
  - Remove users
  - Change user roles

## Alternative: Direct URL Access
If you don't want to edit the file, you can access the member management page directly:
1. Get your folder ID from the URL when viewing the folder
2. Go to: `http://127.0.0.1:5001/folder/<YOUR_FOLDER_ID>/members`

Replace `<YOUR_FOLDER_ID>` with the actual folder ID from your "family" folder.
