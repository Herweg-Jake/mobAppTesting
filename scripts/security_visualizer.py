import os
import json
import argparse
import datetime

def generate_html_report(app_name, result_files):    
    # load all results
    all_issues = []
    for result_file in result_files:
        if os.path.exists(result_file):
            with open(result_file, 'r') as f:
                try:
                    issues = json.load(f)
                    if isinstance(issues, list):
                        all_issues.extend(issues)
                except json.JSONDecodeError:
                    print(f"Warning: Could not parse {result_file} as JSON")
    
    # count issues by type
    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
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
        </style>
    </head>
    <body>
        <h1>Mobile App Security Analysis Report</h1>
        <div>
            <p><strong>App Name:</strong> {app_name}</p>
            <p><strong>Analysis Date:</strong> {now}</p>
            <p><strong>Total Issues Found:</strong> {len(all_issues)}</p>
        </div>
        
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
        </div>
        
        <h2>Issues by Category</h2>
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
        
        <h2>Detailed Issues</h2>
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
            
            html += f"""
                <tr class="{severity_class}">
                    <td>{severity}</td>
                    <td>{description}</td>
                    <td>{location}</td>
                    <td>
                        <button class="collapsible">View Details</button>
                        <div class="content">
                            <pre>{context}</pre>
                        </div>
                    </td>
                </tr>
            """
        
        html += """
            </table>
        </div>
        """
    
    html += """
        </ul>
        
        <script>
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