// Non-macOS: no menu bar UI.
#if !defined(__APPLE__)

#include "swpasskey/ui/menubar.hpp"

namespace swpk::ui {

std::unique_ptr<MenuBar> make_menu_bar(MenuBarDeps) { return nullptr; }

}  // namespace swpk::ui

#endif
