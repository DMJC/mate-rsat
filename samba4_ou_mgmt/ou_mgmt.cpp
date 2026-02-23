#include <gtkmm.h>
#include <ldap.h>

#include <algorithm>
#include <cctype>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace {

struct DirectoryNode {
    std::string dn;
    std::string parent_dn;
    std::string display_name;
    std::string type;
};

std::string trim(const std::string& value) {
    auto first = std::find_if_not(value.begin(), value.end(), [](unsigned char c) { return std::isspace(c); });
    auto last = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char c) { return std::isspace(c); }).base();
    if (first >= last) {
        return "";
    }
    return std::string(first, last);
}

std::string to_lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::string parent_dn_for(const std::string& dn) {
    bool escape = false;
    for (std::size_t i = 0; i < dn.size(); ++i) {
        if (escape) {
            escape = false;
            continue;
        }
        if (dn[i] == '\\') {
            escape = true;
            continue;
        }
        if (dn[i] == ',') {
            return trim(dn.substr(i + 1));
        }
    }
    return "";
}

int dn_depth(const std::string& dn) {
    bool escape = false;
    int depth = 1;
    for (char c : dn) {
        if (escape) {
            escape = false;
            continue;
        }
        if (c == '\\') {
            escape = true;
            continue;
        }
        if (c == ',') {
            ++depth;
        }
    }
    return depth;
}

std::string join_values(const std::vector<std::string>& values) {
    std::ostringstream output;
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i > 0) {
            output << ", ";
        }
        output << values[i];
    }
    return output.str();
}

} // namespace

class Samba4OuMgmtWindow : public Gtk::Window {
public:
    Samba4OuMgmtWindow();
    ~Samba4OuMgmtWindow() override;

private:
    class TreeColumns : public Gtk::TreeModel::ColumnRecord {
    public:
        TreeColumns() {
            add(display_name);
            add(entry_type);
            add(dn);
        }

        Gtk::TreeModelColumn<Glib::ustring> display_name;
        Gtk::TreeModelColumn<Glib::ustring> entry_type;
        Gtk::TreeModelColumn<Glib::ustring> dn;
    };

    void on_connect_clicked();
    void on_tree_selection_changed();
    void refresh_tree(const std::vector<DirectoryNode>& nodes);
    std::string selected_uri() const;
    int selected_port() const;
    bool ldap_connect_and_query(const std::string& uri,
                                const std::string& bind_dn,
                                const std::string& password,
                                const std::string& base_dn,
                                std::vector<DirectoryNode>& nodes,
                                std::map<std::string, std::map<std::string, std::vector<std::string>>>& properties,
                                std::string& error_out);

    Gtk::Box root_box_{Gtk::ORIENTATION_VERTICAL, 8};
    Gtk::Frame connection_frame_{"Samba4 Domain Controller Connection"};
    Gtk::Grid connection_grid_;

    Gtk::Label host_label_{"Host:"};
    Gtk::Entry host_entry_;

    Gtk::Label port_label_{"Port:"};
    Gtk::ComboBoxText port_combo_;

    Gtk::CheckButton ssl_check_{"Use SSL (LDAPS)"};

    Gtk::Label bind_dn_label_{"Bind DN:"};
    Gtk::Entry bind_dn_entry_;

    Gtk::Label password_label_{"Password:"};
    Gtk::Entry password_entry_;

    Gtk::Label base_dn_label_{"Base DN:"};
    Gtk::Entry base_dn_entry_;

    Gtk::Button connect_button_{"Connect"};
    Gtk::Label status_label_;

    Gtk::Paned content_paned_{Gtk::ORIENTATION_HORIZONTAL};

    Gtk::ScrolledWindow tree_scroller_;
    Gtk::TreeView tree_view_;
    TreeColumns tree_columns_;
    Glib::RefPtr<Gtk::TreeStore> tree_store_;

    Gtk::Frame properties_frame_{"Object Properties"};
    Gtk::ScrolledWindow properties_scroller_;
    Gtk::TextView properties_view_;

    std::map<std::string, std::map<std::string, std::vector<std::string>>> entry_properties_;
    LDAP* ldap_handle_{nullptr};
};

Samba4OuMgmtWindow::Samba4OuMgmtWindow() {
    set_title("samba4_ou_mgmt");
    set_default_size(1100, 700);
    add(root_box_);

    connection_frame_.add(connection_grid_);
    connection_grid_.set_row_spacing(6);
    connection_grid_.set_column_spacing(8);
    connection_grid_.set_margin_start(8);
    connection_grid_.set_margin_end(8);
    connection_grid_.set_margin_top(8);
    connection_grid_.set_margin_bottom(8);

    port_combo_.append("389");
    port_combo_.append("636");
    port_combo_.set_active_text("389");

    host_entry_.set_text("localhost");
    bind_dn_entry_.set_placeholder_text("CN=Administrator,CN=Users,DC=example,DC=com");
    password_entry_.set_visibility(false);
    base_dn_entry_.set_placeholder_text("DC=example,DC=com");

    int row = 0;
    connection_grid_.attach(host_label_, 0, row, 1, 1);
    connection_grid_.attach(host_entry_, 1, row, 1, 1);
    connection_grid_.attach(port_label_, 2, row, 1, 1);
    connection_grid_.attach(port_combo_, 3, row, 1, 1);
    ++row;

    connection_grid_.attach(ssl_check_, 0, row, 2, 1);
    ++row;

    connection_grid_.attach(bind_dn_label_, 0, row, 1, 1);
    connection_grid_.attach(bind_dn_entry_, 1, row, 3, 1);
    ++row;

    connection_grid_.attach(password_label_, 0, row, 1, 1);
    connection_grid_.attach(password_entry_, 1, row, 3, 1);
    ++row;

    connection_grid_.attach(base_dn_label_, 0, row, 1, 1);
    connection_grid_.attach(base_dn_entry_, 1, row, 2, 1);
    connection_grid_.attach(connect_button_, 3, row, 1, 1);
    ++row;

    connection_grid_.attach(status_label_, 0, row, 4, 1);
    status_label_.set_halign(Gtk::ALIGN_START);

    root_box_.pack_start(connection_frame_, Gtk::PACK_SHRINK);

    tree_store_ = Gtk::TreeStore::create(tree_columns_);
    tree_view_.set_model(tree_store_);
    tree_view_.append_column("Name", tree_columns_.display_name);
    tree_view_.append_column("Type", tree_columns_.entry_type);
    tree_view_.append_column("DN", tree_columns_.dn);

    tree_scroller_.add(tree_view_);
    tree_scroller_.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC);

    properties_view_.set_editable(false);
    properties_view_.set_monospace(true);
    properties_scroller_.add(properties_view_);
    properties_scroller_.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC);
    properties_frame_.add(properties_scroller_);

    content_paned_.add1(tree_scroller_);
    content_paned_.add2(properties_frame_);
    content_paned_.set_position(600);

    root_box_.pack_start(content_paned_, Gtk::PACK_EXPAND_WIDGET);

    connect_button_.signal_clicked().connect(sigc::mem_fun(*this, &Samba4OuMgmtWindow::on_connect_clicked));
    tree_view_.get_selection()->signal_changed().connect(sigc::mem_fun(*this, &Samba4OuMgmtWindow::on_tree_selection_changed));

    show_all_children();
}

Samba4OuMgmtWindow::~Samba4OuMgmtWindow() {
    if (ldap_handle_ != nullptr) {
        ldap_unbind_ext_s(ldap_handle_, nullptr, nullptr);
        ldap_handle_ = nullptr;
    }
}

std::string Samba4OuMgmtWindow::selected_uri() const {
    const std::string host = trim(host_entry_.get_text());
    const bool use_ssl = ssl_check_.get_active();
    const int port = selected_port();
    const std::string scheme = use_ssl ? "ldaps" : "ldap";
    return scheme + "://" + host + ":" + std::to_string(port);
}

int Samba4OuMgmtWindow::selected_port() const {
    const auto value = port_combo_.get_active_text();
    if (value == "636") {
        return 636;
    }
    return 389;
}

void Samba4OuMgmtWindow::on_connect_clicked() {
    const std::string host = trim(host_entry_.get_text());
    const std::string bind_dn = trim(bind_dn_entry_.get_text());
    const std::string password = password_entry_.get_text();
    const std::string base_dn = trim(base_dn_entry_.get_text());

    if (host.empty() || base_dn.empty()) {
        status_label_.set_text("Host and Base DN are required.");
        return;
    }

    std::vector<DirectoryNode> nodes;
    std::map<std::string, std::map<std::string, std::vector<std::string>>> properties;
    std::string error;

    status_label_.set_text("Connecting to " + selected_uri() + " ...");

    if (!ldap_connect_and_query(selected_uri(), bind_dn, password, base_dn, nodes, properties, error)) {
        status_label_.set_text("Connection/query failed: " + error);
        return;
    }

    entry_properties_ = std::move(properties);
    refresh_tree(nodes);
    status_label_.set_text("Loaded " + std::to_string(nodes.size()) + " entries from directory.");
}

void Samba4OuMgmtWindow::on_tree_selection_changed() {
    auto selection = tree_view_.get_selection();
    if (!selection) {
        return;
    }

    auto iter = selection->get_selected();
    if (!iter) {
        return;
    }

    const auto row = *iter;
    const Glib::ustring dn_value = row[tree_columns_.dn];
    const std::string dn = dn_value.raw();

    std::ostringstream output;
    output << "DN: " << dn << "\n";
    output << "Type: " << row[tree_columns_.entry_type] << "\n\n";

    const auto properties_iter = entry_properties_.find(dn);
    if (properties_iter == entry_properties_.end()) {
        output << "No properties loaded for this entry.";
    } else {
        for (const auto& pair : properties_iter->second) {
            output << pair.first << ": " << join_values(pair.second) << "\n";
        }
    }

    properties_view_.get_buffer()->set_text(output.str());
}

void Samba4OuMgmtWindow::refresh_tree(const std::vector<DirectoryNode>& nodes) {
    tree_store_->clear();

    std::vector<DirectoryNode> sorted = nodes;
    std::sort(sorted.begin(), sorted.end(), [](const DirectoryNode& left, const DirectoryNode& right) {
        const int depth_left = dn_depth(left.dn);
        const int depth_right = dn_depth(right.dn);
        if (depth_left != depth_right) {
            return depth_left > depth_right;
        }
        return left.dn < right.dn;
    });

    std::map<std::string, Gtk::TreeModel::iterator> by_dn;

    for (const auto& node : sorted) {
        Gtk::TreeModel::iterator iter;
        const auto parent_iter = by_dn.find(node.parent_dn);
        if (parent_iter != by_dn.end()) {
            iter = tree_store_->append(parent_iter->second->children());
        } else {
            iter = tree_store_->append();
        }

        auto row = *iter;
        row[tree_columns_.display_name] = node.display_name;
        row[tree_columns_.entry_type] = node.type;
        row[tree_columns_.dn] = node.dn;
        by_dn[node.dn] = iter;
    }

    tree_view_.expand_all();
}

bool Samba4OuMgmtWindow::ldap_connect_and_query(
    const std::string& uri,
    const std::string& bind_dn,
    const std::string& password,
    const std::string& base_dn,
    std::vector<DirectoryNode>& nodes,
    std::map<std::string, std::map<std::string, std::vector<std::string>>>& properties,
    std::string& error_out) {

    if (ldap_handle_ != nullptr) {
        ldap_unbind_ext_s(ldap_handle_, nullptr, nullptr);
        ldap_handle_ = nullptr;
    }

    LDAP* handle = nullptr;
    const int init_rc = ldap_initialize(&handle, uri.c_str());
    if (init_rc != LDAP_SUCCESS) {
        error_out = ldap_err2string(init_rc);
        return false;
    }

    ldap_handle_ = handle;

    int version = LDAP_VERSION3;
    ldap_set_option(ldap_handle_, LDAP_OPT_PROTOCOL_VERSION, &version);

    if (ssl_check_.get_active()) {
        int tls_mode = LDAP_OPT_X_TLS_ALLOW;
        ldap_set_option(ldap_handle_, LDAP_OPT_X_TLS_REQUIRE_CERT, &tls_mode);
    }

    berval credentials;
    credentials.bv_val = const_cast<char*>(password.c_str());
    credentials.bv_len = password.size();

    berval* server_creds = nullptr;
    int bind_rc = ldap_sasl_bind_s(
        ldap_handle_,
        bind_dn.empty() ? nullptr : bind_dn.c_str(),
        LDAP_SASL_SIMPLE,
        &credentials,
        nullptr,
        nullptr,
        &server_creds);

    if (server_creds != nullptr) {
        ber_bvfree(server_creds);
        server_creds = nullptr;
    }

    if (bind_rc != LDAP_SUCCESS) {
        error_out = ldap_err2string(bind_rc);
        return false;
    }

    const char* attrs[] = {
        "cn",
        "ou",
        "name",
        "distinguishedName",
        "objectClass",
        "description",
        "displayName",
        "mail",
        "sAMAccountName",
        "dNSHostName",
        nullptr
    };

    LDAPMessage* search_result = nullptr;
    const char* filter = "(|(objectClass=organizationalUnit)(objectClass=user)(objectClass=computer))";

    int search_rc = ldap_search_ext_s(
        ldap_handle_,
        base_dn.c_str(),
        LDAP_SCOPE_SUBTREE,
        filter,
        const_cast<char**>(attrs),
        0,
        nullptr,
        nullptr,
        nullptr,
        0,
        &search_result);

    if (search_rc != LDAP_SUCCESS) {
        if (search_result != nullptr) {
            ldap_msgfree(search_result);
        }
        error_out = ldap_err2string(search_rc);
        return false;
    }

    std::set<std::string> seen_dns;

    for (LDAPMessage* entry = ldap_first_entry(ldap_handle_, search_result);
         entry != nullptr;
         entry = ldap_next_entry(ldap_handle_, entry)) {
        char* dn_raw = ldap_get_dn(ldap_handle_, entry);
        if (dn_raw == nullptr) {
            continue;
        }

        const std::string dn = dn_raw;
        ldap_memfree(dn_raw);

        std::map<std::string, std::vector<std::string>> entry_map;

        BerElement* ber = nullptr;
        for (char* attr = ldap_first_attribute(ldap_handle_, entry, &ber);
             attr != nullptr;
             attr = ldap_next_attribute(ldap_handle_, entry, ber)) {
            berval** values = ldap_get_values_len(ldap_handle_, entry, attr);
            if (values != nullptr) {
                std::vector<std::string> attr_values;
                for (int i = 0; values[i] != nullptr; ++i) {
                    attr_values.emplace_back(values[i]->bv_val, values[i]->bv_len);
                }
                entry_map[attr] = std::move(attr_values);
                ldap_value_free_len(values);
            }
            ldap_memfree(attr);
        }
        if (ber != nullptr) {
            ber_free(ber, 0);
        }

        auto find_value = [&entry_map](const std::string& key) {
            auto it = entry_map.find(key);
            if (it == entry_map.end() || it->second.empty()) {
                return std::string();
            }
            return it->second.front();
        };

        std::string type = "Unknown";
        const auto object_class_it = entry_map.find("objectClass");
        if (object_class_it != entry_map.end()) {
            for (const auto& cls : object_class_it->second) {
                const std::string lowered = to_lower(cls);
                if (lowered == "computer") {
                    type = "Computer";
                } else if (lowered == "organizationalunit") {
                    type = "OU";
                } else if (lowered == "user" && type == "Unknown") {
                    type = "User";
                }
            }
        }

        std::string display_name = find_value("name");
        if (display_name.empty()) {
            display_name = find_value("cn");
        }
        if (display_name.empty()) {
            display_name = find_value("ou");
        }
        if (display_name.empty()) {
            display_name = dn;
        }

        nodes.push_back(DirectoryNode{dn, parent_dn_for(dn), display_name, type});
        properties[dn] = std::move(entry_map);
        seen_dns.insert(dn);
    }

    ldap_msgfree(search_result);

    if (!seen_dns.count(base_dn)) {
        nodes.push_back(DirectoryNode{base_dn, "", base_dn, "Domain"});
        properties[base_dn] = {
            {"distinguishedName", {base_dn}},
            {"objectClass", {"domain"}}
        };
    }

    return true;
}

int main(int argc, char* argv[]) {
    auto app = Gtk::Application::create(argc, argv, "org.samba4.ou.mgmt");
    Samba4OuMgmtWindow window;
    return app->run(window);
}
