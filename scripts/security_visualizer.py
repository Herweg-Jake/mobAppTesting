import os
import json
import argparse
import datetime

def generate_html_report(app_name, result_files):    
    # load all results
    all_issues = []
    additional_data = {
        "permissions": {},
        "libraries": {},
        "anti_tampering": {}
    }
    
    for result_file in result_files:
        if os.path.exists(result_file):
            try:
                with open(result_file, 'r') as f:
                    data = json.load(f)
                    
                    # handle different result formats
                    if isinstance(data, list):
                        all_issues.extend(data)
                    elif isinstance(data, dict):
                        if "issues" in data:
                            all_issues.extend(data["issues"])
                        
                        if "permissions" in data and "usage" in data:
                            additional_data["permissions"] = data
                        
                        if "libraries" in data and "ad_networks" in data:
                            additional_data["libraries"] = data
                        
                        # check for anti-tampering data by looking for signature verification
                        for issue in data.get("issues", []):
                            if issue.get("type") == "Anti-Tampering" or issue.get("type") == "Root Detection":
                                additional_data["anti_tampering"] = data
                                break
            except json.JSONDecodeError:
                print(f"Warning: Could not parse {result_file} as JSON")
    
    # count issues by type
    issue_counts = {}
    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    type_counts = {}
    
    for issue in all_issues:
        severity = issue.get("severity", "UNKNOWN")
        issue_type = issue.get("type", "UNKNOWN")
        
        if severity in severity_counts:
            severity_counts[severity] += 1
            
        if issue_type not in type_counts:
            type_counts[issue_type] = 0
        type_counts[issue_type] += 1
    
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Analysis Report - {app_name}</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                line-height: 1.6;
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
                color: #333;
            }}
            h1, h2, h3 {{
                color: #2c3e50;
            }}
            .summary-box {{
                display: flex;
                justify-content: space-between;
                margin-bottom: 30px;
            }}
            .summary-item {{
                flex: 1;
                padding: 15px;
                border-radius: 5px;
                color: white;
                text-align: center;
                margin: 0 10px;
            }}
            .high {{
                background-color: #e74c3c;
            }}
            .medium {{
                background-color: #f39c12;
            }}
            .low {{
                background-color: #3498db;
            }}
            .info {{
                background-color: #95a5a6;
            }}
            .chart-container {{
                display: flex;
                margin-bottom: 30px;
            }}
            .bar-chart {{
                flex: 1;
                height: 300px;
                margin: 0 10px;
            }}
            .bar {{
                background-color: #3498db;
                margin-bottom: 5px;
                color: white;
                padding: 5px;
                display: flex;
                justify-content: space-between;
            }}
            .issue-table {{
                width: 100%;
                border-collapse: collapse;
                margin-bottom: 30px;
            }}
            .issue-table th, .issue-table td {{
                border: 1px solid #ddd;
                padding: 8px;
                text-align: left;
            }}
            .issue-table th {{
                background-color: #f2f2f2;
                position: sticky;
                top: 0;
            }}
            .issue-table tr:nth-child(even) {{
                background-color: #f9f9f9;
            }}
            .severity-high {{
                background-color: #ffdddd;
            }}
            .severity-medium {{
                background-color: #ffffdd;
            }}
            .severity-low {{
                background-color: #ddffdd;
            }}
            .severity-info {{
                background-color: #f0f0f0;
            }}
            .collapsible {{
                background-color: #f1f1f1;
                color: #444;
                cursor: pointer;
                padding: 18px;
                width: 100%;
                border: none;
                text-align: left;
                outline: none;
                font-size: 15px;
                margin-bottom: 5px;
            }}
            .active, .collapsible:hover {{
                background-color: #ccc;
            }}
            .content {{
                padding: 0 18px;
                display: none;
                overflow: hidden;
                background-color: #f9f9f9;
                margin-bottom: 10px;
            }}
            pre {{
                background-color: #f8f8f8;
                border: 1px solid #ddd;
                padding: 10px;
                overflow-x: auto;
                white-space: pre-wrap;
                word-wrap: break-word;
            }}
            .permission-chart {{
                width: 100%;
                margin-bottom: a 20px;
            }}
            .permission {{
                margin-bottom: 5px;
                padding: 5px;
                border-radius: 3px;
            }}
            .dangerous {{
                background-color: #ffdddd;
            }}
            .normal {{
                background-color: #ddffdd;
            }}
            .signature {{
                background-color: #ffffdd;
            }}
            .custom {{
                background-color: #ddddff;
            }}
            .used {{
                border-left: 5px solid #27ae60;
            }}
            .unused {{
                border-left: 5px solid #e74c3c;
            }}
            .library-section {{
                margin-bottom: 30px;
            }}
            .defense-section {{
                margin-bottom: 30px;
            }}
            .score-box {{
                display: flex;
                align-items: center;
                justify-content: center;
                width: 80px;
                height: 80px;
                border-radius: 50%;
                color: white;
                font-size: 24px;
                font-weight: bold;
                margin: 20px auto;
            }}
            .score-good {{
                background-color: #27ae60;
            }}
            .score-medium {{
                background-color: #f39c12;
            }}
            .score-bad {{
                background-color: #e74c3c;
            }}
            .tag {{
                display: inline-block;
                padding: 2px 8px;
                border-radius: 12px;
                font-size: 12px;
                margin-right: 5px;
                color: white;
            }}
            .tag-security {{
                background-color: #3498db;
            }}
            .tag-privacy {{
                background-color: #9b59b6;
            }}
            .tab {{
                overflow: hidden;
                border: 1px solid #ccc;
                background-color: #f1f1f1;
                margin-top: 20px;
            }}
            .tab button {{
                background-color: inherit;
                float: left;
                border: none;
                outline: none;
                cursor: pointer;
                padding: 14px 16px;
                transition: 0.3s;
                font-size: 17px;
            }}
            .tab button:hover {{
                background-color: #ddd;
            }}
            .tab button.active {{
                background-color: #ccc;
            }}
            .tabcontent {{
                display: none;
                padding: 20px;
                border: 1px solid #ccc;
                border-top: none;
            }}
        </style>
    </head>
    <body>
        <h1>Mobile App Security Analysis Report</h1>
        <div>
            <p><strong>App Name:</strong> {app_name}</p>
            <p><strong>Analysis Date:</strong> {now}</p>
            <p><strong>Total Issues Found:</strong> {len(all_issues)}</p>
        </div>
        
        <div class="tab">
            <button class="tablinks" onclick="openTab(event, 'Summary')" id="defaultOpen">Summary</button>
            <button class="tablinks" onclick="openTab(event, 'Issues')">Security Issues</button>
            <button class="tablinks" onclick="openTab(event, 'Permissions')">Permissions</button>
            <button class="tablinks" onclick="openTab(event, 'Libraries')">Third-Party Libraries</button>
            <button class="tablinks" onclick="openTab(event, 'Defenses')">Security Defenses</button>
            <button class="tablinks" onclick="openTab(event, 'Recommendations')">Recommendations</button>
        </div>
        
        <div id="Summary" class="tabcontent">
            <h2>Security Summary</h2>
            <div class="summary-box">
                <div class="summary-item high">
                    <h3>High</h3>
                    <p style="font-size: 24px;">{severity_counts["HIGH"]}</p>
                </div>
                <div class="summary-item medium">
                    <h3>Medium</h3>
                    <p style="font-size: 24px;">{severity_counts["MEDIUM"]}</p>
                </div>
                <div class="summary-item low">
                    <h3>Low</h3>
                    <p style="font-size: 24px;">{severity_counts["LOW"]}</p>
                </div>
                <div class="summary-item info">
                    <h3>Info</h3>
                    <p style="font-size: 24px;">{severity_counts["INFO"]}</p>
                </div>
            </div>
            
            <h3>Security Rating</h3>
    """
    
    # security score 
    security_score = 100
    security_score -= severity_counts["HIGH"] * 10
    security_score -= severity_counts["MEDIUM"] * 5
    security_score -= severity_counts["LOW"] * 2
    security_score = max(0, security_score)
    
    if security_score >= 70:
        score_class = "score-good"
        rating_text = "Good"
    elif security_score >= 40:
        score_class = "score-medium"
        rating_text = "Needs Improvement"
    else:
        score_class = "score-bad"
        rating_text = "Poor"
    
    html += f"""
            <div class="{score_class} score-box">
                {security_score}
            </div>
            <p style="text-align: center;"><strong>Rating:</strong> {rating_text}</p>
            
            <h3>Issues by Category</h3>
            <div class="chart-container">
                <div class="bar-chart">
    """
    
    # bar chart
    sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
    max_count = max(type_counts.values()) if type_counts else 0
    
    for issue_type, count in sorted_types:
        width_percent = (count / max_count * 100) if max_count > 0 else 0
        html += f"""
                <div style="display: flex; margin-bottom: 10px;">
                    <div style="width: 200px; text-align: right; padding-right: 10px;">{issue_type}</div>
                    <div class="bar" style="width: {width_percent}%;">
                        <span>{count}</span>
                    </div>
                </div>
        """
    
    html += """
            </div>
        </div>
        </div>
        <div id="Issues" class="tabcontent">
            <h2>Detailed Security Issues</h2>
    """
    
    # group issues by type
    issues_by_type = {}
    for issue in all_issues:
        issue_type = issue.get("type", "UNKNOWN")
        if issue_type not in issues_by_type:
            issues_by_type[issue_type] = []
        issues_by_type[issue_type].append(issue)
    
    # collapsible sections for each issue type
    for issue_type, issues in issues_by_type.items():
        html += f"""
        <button class="collapsible">{issue_type} ({len(issues)})</button>
        <div class="content">
            <table class="issue-table">
                <tr>
                    <th>Severity</th>
                    <th>Description</th>
                    <th>Location</th>
                    <th>Details</th>
                </tr>
        """
        
        for issue in issues:
            severity = issue.get("severity", "UNKNOWN")
            description = issue.get("description", "No description")
            location = issue.get("location", "Unknown")
            context = issue.get("context", "")
            
            severity_class = ""
            if severity == "HIGH":
                severity_class = "severity-high"
            elif severity == "MEDIUM":
                severity_class = "severity-medium"
            elif severity == "LOW":
                severity_class = "severity-low"
            elif severity == "INFO":
                severity_class = "severity-info"
            
            html += f"""
                <tr class="{severity_class}">
                    <td>{severity}</td>
                    <td>{description}</td>
                    <td>{location}</td>
                    <td>
            """
            
            if context:
                html += f"""
                        <button class="collapsible">View Details</button>
                        <div class="content">
                            <pre>{context}</pre>
                        </div>
                """
            else:
                html += "No additional details"
                
            html += """
                    </td>
                </tr>
            """
        
        html += """
            </table>
        </div>
        """
    
    # permissions tab
    html += """
        </div>
        
        <div id="Permissions" class="tabcontent">
            <h2>Permission Analysis</h2>
    """
    
    if additional_data["permissions"]:
        permissions = additional_data["permissions"].get("permissions", {})
        usage = additional_data["permissions"].get("usage", {})
        
        # count permissions by type
        dangerous_count = len(permissions.get("dangerous", []))
        signature_count = len(permissions.get("signature", []))
        normal_count = len(permissions.get("normal", []))
        custom_count = len(permissions.get("custom", []))
        
        total_perms = dangerous_count + signature_count + normal_count + custom_count
        used_count = sum(1 for p, d in usage.items() if d.get("used", False))
        unused_count = total_perms - used_count
        
        html += f"""
            <div class="summary-box">
                <div class="summary-item high">
                    <h3>Dangerous</h3>
                    <p style="font-size: 24px;">{dangerous_count}</p>
                </div>
                <div class="summary-item medium">
                    <h3>Signature</h3>
                    <p style="font-size: 24px;">{signature_count}</p>
                </div>
                <div class="summary-item low">
                    <h3>Normal</h3>
                    <p style="font-size: 24px;">{normal_count}</p>
                </div>
                <div class="summary-item info">
                    <h3>Custom</h3>
                    <p style="font-size: 24px;">{custom_count}</p>
                </div>
            </div>
            
            <h3>Permission Usage</h3>
            <div style="display: flex; margin-bottom: 20px;">
                <div style="flex: 1; text-align: center;">
                    <h4>Used Permissions</h4>
                    <div class="score-box score-good">{used_count}</div>
                </div>
                <div style="flex: 1; text-align: center;">
                    <h4>Unused Permissions</h4>
                    <div class="score-box score-bad">{unused_count}</div>
                </div>
            </div>
            
            <h3>Dangerous Permissions</h3>
            <div class="permission-chart">
        """
        
        # show dangerous permissions
        for perm in permissions.get("dangerous", []):
            perm_used = perm in usage and usage[perm].get("used", False)
            perm_class = "used" if perm_used else "unused"
            perm_short = usage.get(perm, {}).get("short_name", perm.split(".")[-1])
            
            html += f"""
                <div class="permission dangerous {perm_class}">
                    {perm_short} - <strong>{"Used" if perm_used else "Unused"}</strong>
                </div>
            """
        
        html += """
            </div>
        """
    else:
        html += "<p>No detailed permission data available.</p>"
    
    # libraries tab
    html += """
        </div>
        
        <div id="Libraries" class="tabcontent">
            <h2>Third-Party Library Analysis</h2>
    """
    
    if additional_data["libraries"]:
        libraries = additional_data["libraries"].get("libraries", {})
        ad_networks = additional_data["libraries"].get("ad_networks", {})
        tracking_libs = additional_data["libraries"].get("tracking_libraries", {})
        
        # libraries section
        html += f"""
            <div class="library-section">
                <h3>Detected Libraries ({len(libraries)})</h3>
                <ul>
        """
        
        for lib_name, lib_data in libraries.items():
            import_count = lib_data.get("import_count", 0)
            html += f"<li><strong>{lib_name}</strong> - {import_count} imports</li>"
        
        html += """
                </ul>
            </div>
            
            <div class="library-section">
                <h3>Ad Networks</h3>
        """
        
        if ad_networks:
            html += f"""
                <p>Detected {len(ad_networks)} ad networks:</p>
                <ul>
            """
            
            for network_name in ad_networks.keys():
                html += f"<li>{network_name}</li>"
            
            html += "</ul>"
        else:
            html += "<p>No ad networks detected.</p>"
        
        html += """
            </div>
            
            <div class="library-section">
                <h3>Analytics and Tracking</h3>
        """
        
        if tracking_libs:
            html += f"""
                <p>Detected {len(tracking_libs)} tracking/analytics libraries:</p>
                <ul>
            """
            
            for lib_name in tracking_libs.keys():
                html += f"<li>{lib_name}</li>"
            
            html += "</ul>"
        else:
            html += "<p>No tracking libraries detected.</p>"
        
        html += """
            </div>
        """
    else:
        html += "<p>No third-party library data available.</p>"
    
    html += """
        </div>
        
        <div id="Defenses" class="tabcontent">
            <h2>Security Defense Mechanisms</h2>
    """
    
    # anti-tampering mechanisms
    if additional_data["anti_tampering"]:
        signature_issues = [i for i in all_issues if i.get("type") == "Anti-Tampering"]
        root_issues = [i for i in all_issues if i.get("type") == "Root Detection"]
        emulator_issues = [i for i in all_issues if i.get("type") == "Emulator Detection"]
        debug_issues = [i for i in all_issues if i.get("type") == "Anti-Debugging"]
        
        html += f"""
            <div class="defense-section">
                <h3>Anti-Tampering Mechanisms</h3>
                <p>The app implements {len(signature_issues)} signature verification mechanisms.</p>
            </div>
            
            <div class="defense-section">
                <h3>Root Detection</h3>
                <p>The app implements {len(root_issues)} root detection mechanisms.</p>
            </div>
            
            <div class="defense-section">
                <h3>Emulator Detection</h3>
                <p>The app implements {len(emulator_issues)} emulator detection mechanisms.</p>
            </div>
            
            <div class="defense-section">
                <h3>Anti-Debugging</h3>
                <p>The app implements {len(debug_issues)} anti-debugging mechanisms.</p>
            </div>
        """
        
        # calculate  score
        defense_score = min(100, 
                           (len(signature_issues) * 15 + 
                            len(root_issues) * 15 + 
                            len(emulator_issues) * 10 + 
                            len(debug_issues) * 10))
        
        if defense_score >= 60:
            defense_class = "score-good"
            defense_text = "Strong"
        elif defense_score >= 30:
            defense_class = "score-medium"
            defense_text = "Moderate"
        else:
            defense_class = "score-bad"
            defense_text = "Weak"
        
        html += f"""
            <h3>Overall Defense Rating</h3>
            <div class="{defense_class} score-box">
                {defense_score}
            </div>
            <p style="text-align: center;"><strong>Rating:</strong> {defense_text}</p>
        """
    else:
        html += """
            <p>No anti-tampering mechanisms detected.</p>
            <div class="score-box score-bad">
                0
            </div>
            <p style="text-align: center;"><strong>Rating:</strong> Weak</p>
        """
    
    html += """
            </ul>
        </div>
        
        <script>
            // for tabs
            function openTab(evt, tabName) {
                var i, tabcontent, tablinks;
                tabcontent = document.getElementsByClassName("tabcontent");
                for (i = 0; i < tabcontent.length; i++) {
                    tabcontent[i].style.display = "none";
                }
                tablinks = document.getElementsByClassName("tablinks");
                for (i = 0; i < tablinks.length; i++) {
                    tablinks[i].className = tablinks[i].className.replace(" active", "");
                }
                document.getElementById(tabName).style.display = "block";
                evt.currentTarget.className += " active";
            }
            
            document.getElementById("defaultOpen").click();
            
            // for collapsible sections
            var coll = document.getElementsByClassName("collapsible");
            for (var i = 0; i < coll.length; i++) {
                coll[i].addEventListener("click", function() {
                    this.classList.toggle("active");
                    var content = this.nextElementSibling;
                    if (content.style.display === "block") {
                        content.style.display = "none";
                    } else {
                        content.style.display = "block";
                    }
                });
            }
        </script>
    </body>
    </html>
    """
    
    return html

def main():
    parser = argparse.ArgumentParser(description="Generate security analysis report")
    parser.add_argument("app_name", help="Name of the analyzed application")
    parser.add_argument("result_files", nargs="+", help="JSON result files from security analysis")
    parser.add_argument("-o", "--output", default="security_report.html", help="Output HTML report file")
    
    args = parser.parse_args()
    
    html_report = generate_html_report(args.app_name, args.result_files)
    
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(html_report)
    
    print(f"Report generated: {args.output}")

if __name__ == "__main__":
    main()