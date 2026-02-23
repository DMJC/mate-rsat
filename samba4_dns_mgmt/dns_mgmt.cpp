#include <gtkmm.h>

#include <array>
#include <cstdint>
#include <optional>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

namespace {

class DnsColumns : public Gtk::TreeModel::ColumnRecord {
public:
    DnsColumns() {
        add(col_zone);
        add(col_name);
        add(col_type);
        add(col_data);
        add(col_ttl);
        add(col_is_zone);
    }

    Gtk::TreeModelColumn<Glib::ustring> col_zone;
    Gtk::TreeModelColumn<Glib::ustring> col_name;
    Gtk::TreeModelColumn<Glib::ustring> col_type;
    Gtk::TreeModelColumn<Glib::ustring> col_data;
    Gtk::TreeModelColumn<Glib::ustring> col_ttl;
    Gtk::TreeModelColumn<bool> col_is_zone;
};

struct ParsedRecord {
    Glib::ustring name;
    Glib::ustring type;
    Glib::ustring data;
    Glib::ustring ttl;
};

std::string quote_arg(const std::string& value) {
    std::string quoted = "'";
    for (const char ch : value) {
        if (ch == '\'') {
            quoted += "'\\''";
        } else {
            quoted.push_back(ch);
        }
    }
    quoted.push_back('\'');
    return quoted;
}

std::string quote_arg(const Glib::ustring& value) {
    return quote_arg(value.raw());
}

std::optional<std::pair<std::string, std::string>> ptr_target_from_ipv4(const std::string& ipv4) {
    std::array<int, 4> octets{};
    char dot1 = 0;
    char dot2 = 0;
    char dot3 = 0;
    std::istringstream iss(ipv4);
    if (!(iss >> octets[0] >> dot1 >> octets[1] >> dot2 >> octets[2] >> dot3 >> octets[3])) {
        return std::nullopt;
    }
    if (dot1 != '.' || dot2 != '.' || dot3 != '.') {
        return std::nullopt;
    }
    for (const int octet : octets) {
        if (octet < 0 || octet > 255) {
            return std::nullopt;
        }
    }

    std::ostringstream zone;
    zone << octets[2] << '.' << octets[1] << '.' << octets[0] << ".in-addr.arpa";

    return std::make_pair(std::to_string(octets[3]), zone.str());
}

class RecordDialog : public Gtk::Dialog {
public:
    RecordDialog(Gtk::Window& parent,
                 const Glib::ustring& type,
                 const Glib::ustring& zone,
                 const Glib::ustring& default_name)
        : Gtk::Dialog("Create " + type + " record", parent, true),
          record_type(type),
          name_label("Name"),
          data_label("Data"),
          ttl_label("TTL (optional)"),
          ptr_check("Create matching PTR record") {
        set_default_size(420, 220);

        auto* content = get_content_area();
        content->set_spacing(8);

        zone_label.set_text("Zone: " + zone);
        zone_label.set_halign(Gtk::ALIGN_START);

        name_entry.set_text(default_name);

        if (record_type == "A") {
            data_label.set_text("IPv4 address");
        } else if (record_type == "AAAA") {
            data_label.set_text("IPv6 address");
        } else if (record_type == "SRV") {
            data_label.set_text("target port priority weight");
        } else if (record_type == "CNAME") {
            data_label.set_text("Canonical target (FQDN)");
        } else if (record_type == "TXT") {
            data_label.set_text("Text value");
        }

        grid.set_row_spacing(6);
        grid.set_column_spacing(8);
        grid.attach(zone_label, 0, 0, 2, 1);
        grid.attach(name_label, 0, 1, 1, 1);
        grid.attach(name_entry, 1, 1, 1, 1);
        grid.attach(data_label, 0, 2, 1, 1);
        grid.attach(data_entry, 1, 2, 1, 1);
        grid.attach(ttl_label, 0, 3, 1, 1);
        grid.attach(ttl_entry, 1, 3, 1, 1);

        if (record_type == "A") {
            grid.attach(ptr_check, 1, 4, 1, 1);
        }

        content->pack_start(grid, Gtk::PACK_EXPAND_WIDGET);

        add_button("Cancel", Gtk::RESPONSE_CANCEL);
        add_button("Create", Gtk::RESPONSE_OK);

        show_all_children();
    }

    Glib::ustring get_name() const { return name_entry.get_text(); }
    Glib::ustring get_data() const { return data_entry.get_text(); }
    Glib::ustring get_ttl() const { return ttl_entry.get_text(); }
    bool create_ptr() const { return ptr_check.get_active(); }

private:
    Glib::ustring record_type;
    Gtk::Grid grid;
    Gtk::Label zone_label;
    Gtk::Label name_label;
    Gtk::Label data_label;
    Gtk::Label ttl_label;
    Gtk::Entry name_entry;
    Gtk::Entry data_entry;
    Gtk::Entry ttl_entry;
    Gtk::CheckButton ptr_check;
};

class DnsWindow : public Gtk::Window {
public:
    DnsWindow() : connect_button("Connect / Refresh") {
        set_title("samba4-dns-mgmt");
        set_default_size(920, 560);

        container.set_orientation(Gtk::ORIENTATION_VERTICAL);
        container.set_spacing(8);
        container.set_margin_top(8);
        container.set_margin_bottom(8);
        container.set_margin_start(8);
        container.set_margin_end(8);

        setup_connection_row();
        setup_tree();

        add(container);
        show_all_children();
    }

private:
    void setup_connection_row() {
        auto* row = Gtk::make_managed<Gtk::Grid>();
        row->set_row_spacing(6);
        row->set_column_spacing(8);

        server_label.set_text("Domain Controller");
        user_label.set_text("Username");
        pass_label.set_text("Password");

        server_entry.set_placeholder_text("dc1.example.com");
        user_entry.set_placeholder_text("administrator");
        pass_entry.set_visibility(false);

        connect_button.signal_clicked().connect(sigc::mem_fun(*this, &DnsWindow::load_records));

        row->attach(server_label, 0, 0, 1, 1);
        row->attach(server_entry, 1, 0, 1, 1);
        row->attach(user_label, 2, 0, 1, 1);
        row->attach(user_entry, 3, 0, 1, 1);
        row->attach(pass_label, 4, 0, 1, 1);
        row->attach(pass_entry, 5, 0, 1, 1);
        row->attach(connect_button, 6, 0, 1, 1);

        container.pack_start(*row, Gtk::PACK_SHRINK);

        status_label.set_halign(Gtk::ALIGN_START);
        container.pack_start(status_label, Gtk::PACK_SHRINK);
    }

    void setup_tree() {
        tree_store = Gtk::TreeStore::create(columns);
        tree.set_model(tree_store);
        tree.append_column("Zone", columns.col_zone);
        tree.append_column("Name", columns.col_name);
        tree.append_column("Type", columns.col_type);
        tree.append_column("Data", columns.col_data);
        tree.append_column("TTL", columns.col_ttl);

        tree.add_events(Gdk::BUTTON_PRESS_MASK);
        tree.signal_button_press_event().connect(sigc::mem_fun(*this, &DnsWindow::on_tree_button_press), false);

        scroll.add(tree);
        scroll.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC);

        container.pack_start(scroll, Gtk::PACK_EXPAND_WIDGET);

        create_menu();
    }

    void create_menu() {
        add_a.signal_activate().connect(sigc::bind(sigc::mem_fun(*this, &DnsWindow::show_create_record_dialog), Glib::ustring("A")));
        add_aaaa.signal_activate().connect(sigc::bind(sigc::mem_fun(*this, &DnsWindow::show_create_record_dialog), Glib::ustring("AAAA")));
        add_srv.signal_activate().connect(sigc::bind(sigc::mem_fun(*this, &DnsWindow::show_create_record_dialog), Glib::ustring("SRV")));
        add_cname.signal_activate().connect(sigc::bind(sigc::mem_fun(*this, &DnsWindow::show_create_record_dialog), Glib::ustring("CNAME")));
        add_txt.signal_activate().connect(sigc::bind(sigc::mem_fun(*this, &DnsWindow::show_create_record_dialog), Glib::ustring("TXT")));

        add_a.set_label("Create A record");
        add_aaaa.set_label("Create AAAA record");
        add_srv.set_label("Create SRV record");
        add_cname.set_label("Create CNAME record");
        add_txt.set_label("Create TXT record");

        menu.append(add_a);
        menu.append(add_aaaa);
        menu.append(add_srv);
        menu.append(add_cname);
        menu.append(add_txt);
        menu.show_all();
    }

    bool on_tree_button_press(GdkEventButton* button_event) {
        if (!button_event || button_event->type != GDK_BUTTON_PRESS || button_event->button != 3) {
            return false;
        }

        Gtk::TreeModel::Path path;
        Gtk::TreeViewColumn* column = nullptr;
        int cell_x = 0;
        int cell_y = 0;

        if (!tree.get_path_at_pos(static_cast<int>(button_event->x), static_cast<int>(button_event->y), path, column, cell_x, cell_y)) {
            return false;
        }

        tree.set_cursor(path);
        right_click_selection = path;
        menu.popup_at_pointer(reinterpret_cast<GdkEvent*>(button_event));
        return true;
    }

    std::string credentials_arg() const {
        return quote_arg(user_entry.get_text() + "%" + pass_entry.get_text());
    }

    std::optional<std::string> selected_zone() const {
        if (!right_click_selection) {
            return std::nullopt;
        }
        auto iter = tree_store->get_iter(*right_click_selection);
        if (!iter) {
            return std::nullopt;
        }

        auto row = *iter;
        if (row[columns.col_is_zone]) {
            const Glib::ustring zone = row[columns.col_zone];
            return zone.raw();
        }

        auto parent = iter->parent();
        if (parent) {
            auto parent_row = *parent;
            const Glib::ustring zone = parent_row[columns.col_zone];
            return zone.raw();
        }

        return std::nullopt;
    }

    std::string selected_name_default() const {
        if (!right_click_selection) {
            return "@";
        }
        auto iter = tree_store->get_iter(*right_click_selection);
        if (!iter) {
            return "@";
        }

        auto row = *iter;
        if (row[columns.col_is_zone]) {
            return "@";
        }

        const Glib::ustring name_value = row[columns.col_name];
        const auto name = name_value.raw();
        return name.empty() ? "@" : name;
    }

    bool run_command(const std::string& command, std::string& output, std::string& error) {
        int exit_status = -1;
        try {
            Glib::spawn_command_line_sync(command, &output, &error, &exit_status);
        } catch (const Glib::SpawnError& ex) {
            error = ex.what();
            return false;
        }
        return exit_status == 0;
    }

    std::vector<std::string> list_zones() {
        std::vector<std::string> zones;
        std::string output;
        std::string error;
        const std::string cmd = "samba-tool dns zonelist " + quote_arg(server_entry.get_text()) +
                                " -U " + credentials_arg();

        if (!run_command(cmd, output, error)) {
            status_label.set_text("Unable to list zones: " + error);
            return zones;
        }

        std::istringstream stream(output);
        std::string line;
        const std::regex zone_regex(R"(pszZoneName\s*:\s*([^\s]+))", std::regex::icase);
        std::smatch match;
        while (std::getline(stream, line)) {
            if (std::regex_search(line, match, zone_regex) && match.size() > 1) {
                zones.push_back(match[1]);
            }
        }

        return zones;
    }

    std::vector<ParsedRecord> parse_records(const std::string& text) {
        std::vector<ParsedRecord> records;
        std::istringstream stream(text);
        std::string line;
        std::string current_name = "@";
        std::string current_ttl;

        const std::regex name_regex(R"(Name=([^,]+))", std::regex::icase);
        const std::regex ttl_regex(R"(TTL=([0-9]+))", std::regex::icase);
        const std::regex type_regex(R"(^\s*([A-Z]+):\s*(.+)$)");
        std::smatch match;

        while (std::getline(stream, line)) {
            if (std::regex_search(line, match, name_regex) && match.size() > 1) {
                current_name = match[1];
            }
            if (std::regex_search(line, match, ttl_regex) && match.size() > 1) {
                current_ttl = match[1];
            }
            if (std::regex_search(line, match, type_regex) && match.size() > 2) {
                ParsedRecord parsed;
                parsed.name = current_name;
                parsed.type = match[1].str();
                parsed.data = match[2].str();
                parsed.ttl = current_ttl;
                records.push_back(parsed);
            }
        }

        return records;
    }

    void load_records() {
        tree_store->clear();

        if (server_entry.get_text().empty() || user_entry.get_text().empty()) {
            status_label.set_text("Server and username are required.");
            return;
        }

        const auto zones = list_zones();
        if (zones.empty()) {
            if (status_label.get_text().empty()) {
                status_label.set_text("No zones returned by server.");
            }
            return;
        }

        std::size_t total = 0;
        for (const auto& zone : zones) {
            auto zone_row = *(tree_store->append());
            zone_row[columns.col_zone] = zone;
            zone_row[columns.col_is_zone] = true;

            std::string output;
            std::string error;
            const std::string cmd = "samba-tool dns query " + quote_arg(server_entry.get_text()) + " " +
                                    quote_arg(zone) + " @ ALL -U " + credentials_arg();

            if (!run_command(cmd, output, error)) {
                auto child = *(tree_store->append(zone_row.children()));
                child[columns.col_zone] = zone;
                child[columns.col_name] = "<query failed>";
                child[columns.col_data] = error;
                child[columns.col_is_zone] = false;
                continue;
            }

            const auto records = parse_records(output);
            for (const auto& record : records) {
                auto child = *(tree_store->append(zone_row.children()));
                child[columns.col_zone] = zone;
                child[columns.col_name] = record.name;
                child[columns.col_type] = record.type;
                child[columns.col_data] = record.data;
                child[columns.col_ttl] = record.ttl;
                child[columns.col_is_zone] = false;
                ++total;
            }
        }

        status_label.set_text("Loaded " + std::to_string(total) + " DNS records across " + std::to_string(zones.size()) + " zone(s).");
    }

    void show_error(const Glib::ustring& message) {
        Gtk::MessageDialog dialog(*this, "Operation failed", false, Gtk::MESSAGE_ERROR, Gtk::BUTTONS_OK, true);
        dialog.set_secondary_text(message);
        dialog.run();
    }

    void show_info(const Glib::ustring& message) {
        Gtk::MessageDialog dialog(*this, "Success", false, Gtk::MESSAGE_INFO, Gtk::BUTTONS_OK, true);
        dialog.set_secondary_text(message);
        dialog.run();
    }

    void show_create_record_dialog(const Glib::ustring& type) {
        const auto zone_opt = selected_zone();
        if (!zone_opt) {
            show_error("Please right-click a zone or record first.");
            return;
        }

        const Glib::ustring zone = *zone_opt;
        RecordDialog dialog(*this, type, zone, selected_name_default());

        if (dialog.run() != Gtk::RESPONSE_OK) {
            return;
        }

        if (dialog.get_name().empty() || dialog.get_data().empty()) {
            show_error("Name and data are required.");
            return;
        }

        const std::string ttl = dialog.get_ttl();
        std::string add_cmd = "samba-tool dns add " + quote_arg(server_entry.get_text()) + " " +
                              quote_arg(zone) + " " + quote_arg(dialog.get_name()) + " " +
                              quote_arg(type) + " " + quote_arg(dialog.get_data()) +
                              " -U " + credentials_arg();

        if (!ttl.empty()) {
            add_cmd += " --ttl=" + quote_arg(ttl);
        }

        std::string output;
        std::string error;
        if (!run_command(add_cmd, output, error)) {
            show_error(error);
            return;
        }

        if (type == "A" && dialog.create_ptr()) {
            const auto ptr_target = ptr_target_from_ipv4(dialog.get_data());
            if (!ptr_target) {
                show_error("A record created, but PTR creation skipped: invalid IPv4 address.");
            } else {
                std::string fqdn = dialog.get_name();
                if (fqdn == "@") {
                    fqdn = zone;
                } else if (fqdn.find('.') == Glib::ustring::npos) {
                    fqdn += "." + zone;
                }

                if (fqdn.back() != '.') {
                    fqdn += ".";
                }

                std::string ptr_cmd = "samba-tool dns add " + quote_arg(server_entry.get_text()) + " " +
                                      quote_arg(ptr_target->second) + " " + quote_arg(ptr_target->first) +
                                      " PTR " + quote_arg(fqdn) + " -U " + credentials_arg();
                std::string ptr_output;
                std::string ptr_error;
                if (!run_command(ptr_cmd, ptr_output, ptr_error)) {
                    show_error("A record created. PTR creation failed: " + ptr_error);
                }
            }
        }

        show_info(type + " record created successfully.");
        load_records();
    }

    Gtk::Box container;

    Gtk::Label server_label;
    Gtk::Label user_label;
    Gtk::Label pass_label;
    Gtk::Entry server_entry;
    Gtk::Entry user_entry;
    Gtk::Entry pass_entry;
    Gtk::Button connect_button;
    Gtk::Label status_label;

    Gtk::ScrolledWindow scroll;
    Gtk::TreeView tree;
    Glib::RefPtr<Gtk::TreeStore> tree_store;
    DnsColumns columns;

    Gtk::Menu menu;
    Gtk::MenuItem add_a;
    Gtk::MenuItem add_aaaa;
    Gtk::MenuItem add_srv;
    Gtk::MenuItem add_cname;
    Gtk::MenuItem add_txt;
    std::optional<Gtk::TreeModel::Path> right_click_selection;
};

}  // namespace

int main(int argc, char* argv[]) {
    auto app = Gtk::Application::create(argc, argv, "org.mate.rsat.samba4_dns_mgmt");
    DnsWindow window;
    return app->run(window);
}
