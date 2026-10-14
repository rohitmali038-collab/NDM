Network Traffic Analyzer — UI-only updates

Files included:
- frontend/dashboard.py
- frontend/overview.py
- frontend/inspection.py
- frontend/speed_test.py
- frontend/ndm_scanner.py
- frontend/main_window.py

Only Speed Test and NDM Scanner page-level styling was changed in this pass:
- unified dark navy page background
- dark input fields and dropdown menus
- readable dark text areas and tables
- consistent tabs, scrollbars, and progress bars

The Dashboard, Overview, Inspection, and Main Window files are included from the uploaded versions and otherwise unchanged. No backend logic or page functionality was intentionally modified.

To apply:
1. Back up your existing frontend folder.
2. Copy the included files into your project's frontend folder, replacing the same-named files.
3. Run `python main.py`.

Note: This package does not include backend modules or gui/app_state.py; retain your existing project files for those dependencies.
