/**
 * Downloads a report as PDF using pdfmake
 * @param {string} reportId - The UUID of the report
 * @param {string} reportName - Optional report name for the filename
 */
function downloadReportAsPdf(reportId, reportName = 'report') {
    const pdfBtn = document.getElementById('downloadPdfBtn');
    
    // Show loading state if button exists
    if (pdfBtn) {
        pdfBtn.disabled = true;
        pdfBtn.textContent = 'Generating PDF...';
    }

    fetch(`/reports/${reportId}/pdf/`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            return response.json();
        })
        .then(data => {
            const docDefinition = createPdfDefinition(data);
            const filename = `${reportName.replace(/[^a-z0-9]/gi, '_')}.pdf`;
            pdfMake.createPdf(docDefinition).download(filename);
        })
        .catch(error => {
            console.error('PDF generation failed:', error);
            alert(`Failed to generate PDF: ${error.message}`);
        })
        .finally(() => {
            if (pdfBtn) {
                pdfBtn.disabled = false;
                pdfBtn.textContent = 'Download PDF';
            }
        });
}

// =============================================================================
// Javascript recreation of HTML styling for PDF generation using pdfMake
// =============================================================================
function createPdfDefinition(data) {

    // ── Palette — mirrors the CSS variables exactly ───────────────────────────
    const C = {
        ink:       '#0a0a0a',
        mid:       '#3d3d3d',
        light:     '#717171',
        rule:      '#c8c8c8',
        ruleLight: '#e8e8e8',
        surface:   '#fafafa',
        white:     '#ffffff',
        tableHead: '#f5f7f9',
    };

    // A4 page minus 40 + 40 margins = 515 pt usable width
    const W = 515;

    const doc = {
        pageSize:     'A4',
        pageMargins:  [40, 55, 40, 55],
        defaultStyle: { font: 'Roboto', fontSize: 9, color: C.ink, lineHeight: 1.5 },
        content:      [],
    };

    // ── Helper: full-width horizontal canvas rule ─────────────────────────────
    // mg = [left, top, right, bottom]
    function hRule(color, weight, mg) {
        return {
            canvas: [{ type: 'line', x1: 0, y1: 0, x2: W, y2: 0, lineWidth: weight, lineColor: color }],
            margin: mg || [0, 0, 0, 0],
        };
    }

    // ── Helper: section heading — replicates .rp-section-heading ─────────────
    // Returns an ARRAY of two items (text node + rule) so callers can spread it.
    function sectionHead(label) {
        return [
            {
                text:             label.toUpperCase(),
                fontSize:         7,
                bold:             true,
                color:            C.light,
                characterSpacing: 2,
                margin:           [0, 22, 0, 6],
            },
            hRule(C.rule, 0.5, [0, 0, 0, 12]),
        ];
    }

    // ── Helper: sub-label — replicates .rp-sub-label ─────────────────────────
    function subLabel(text) {
        return {
            text:             text.toUpperCase(),
            fontSize:         6.5,
            bold:             true,
            color:            C.ink,
            characterSpacing: 1.5,
            margin:           [0, 0, 0, 3],
        };
    }

    // ── Helper: pill row — replicates .rp-pill-list / .rp-pill ───────────────
    // pdfMake cannot wrap a table row onto multiple lines, so for long element
    // lists (> 5) we fall back to Roboto dot-separated inline text.
    function pillRow(items) {
        if (!items || !items.length) return null;
    
        if (items.length > 5) {
            return {
                text:   items.join('  ·  '),
                fontSize: 7.5,
                font:   'Roboto',
                color:  C.mid,
                margin: [0, 0, 0, 10],
            };
        }
    
        return {
            table: {
                widths: items.map(() => 'auto'),
                body: [
                    items.map(item => ({
                        text:     String(item),
                        fontSize: 7.5,
                        font:     'Roboto',
                        color:    C.mid,
                    })),
                ],
            },
            layout: {
                hLineWidth: () => 0.5,
                vLineWidth: () => 0.5,
                hLineColor: () => C.rule,
                vLineColor: () => C.rule,
                fillColor:  () => C.surface,
                paddingLeft:   () => 6,
                paddingRight:  () => 6,
                paddingTop:    () => 3,
                paddingBottom: () => 0,
            },
            margin: [0, 0, 0, 10],
        };
    }

    // ── Helper: recommendation boxes — replicates .rp-rec-grid / .rp-rec-box ─
    // Must be a table (not a stack) because only table cells support fillColor
    // and border styling in pdfMake.
    function recBoxes(easyFix, longFix) {
        const cells  = [];
        const widths = [];
    
        const makeCell = (title, body) => ({
            stack: [
                {
                    text:             title,
                    fontSize:         6.5,
                    bold:             true,
                    color:            C.ink,
                    characterSpacing: 1,
                    margin:           [0, 0, 0, 4],
                },
                {
                    text:       body,
                    fontSize:   8,
                    color:      C.mid,
                    lineHeight: 1.5,
                },
            ],
        });
    
        if (easyFix) { cells.push(makeCell('QUICK FIX',     easyFix)); widths.push('*'); }
        if (longFix)  { cells.push(makeCell('LONG-TERM FIX', longFix)); widths.push('*'); }
        if (!cells.length) return null;
    
        return {
            table: { widths, body: [cells] },
            layout: {
                hLineWidth: () => 0.5,
                vLineWidth: () => 0.5,
                hLineColor: () => C.ruleLight,
                vLineColor: () => C.ruleLight,
                fillColor:  () => C.surface,
                paddingLeft:   () => 10,
                paddingRight:  () => 10,
                paddingTop:    () => 8,
                paddingBottom: () => 8,
            },
            margin: [0, 0, 0, 0],
        };
    }

    // ── Helper: build the body-row stack for one vuln card ───────────────────
    function buildVulnBody(risk) {
        const stack    = [];
        const overview = risk.Overview    || risk.overview    || '';
        const elements = risk['Affected Elements'] || risk.affected_elements || [];
        const rec      = risk.Recommendation      || {};
        const easyFix  = rec.easy_fix        || risk.easy_fix        || '';
        const longFix  = rec.long_term_fix   || risk.long_term_fix   || '';
    
        if (overview) {
            stack.push({
                text:       overview,
                fontSize:   8.5,
                color:      C.mid,
                lineHeight: 1.6,
                margin:     [0, 0, 0, 10],
            });
        }
    
        if (elements.length) {
            stack.push(subLabel('Affected  Elements'));
            const pills = pillRow(elements);
            if (pills) stack.push(pills);
        }
    
        if (easyFix || longFix) {
            stack.push(subLabel('Recommendations'));
            const recs = recBoxes(easyFix, longFix);
            if (recs) stack.push(recs);
        }
    
        return stack;
    }


    // ═══════════════════════════════════════════════════════════
    // 0. Masthead — replicates .rp-masthead
    // ═══════════════════════════════════════════════════════════

    const overview  = data.overview || {};
    const orgName   = overview['Organization Name'] || '';
    const reportTitle = data.report_name || `Security Assessment — ${orgName}`;

    doc.content.push(
        // Eyebrow — .rp-masthead-eyebrow
        {
            text:             'CYBERSECURITY  ASSESSMENT  REPORT',
            fontSize:         6.5,
            bold:             true,
            color:            C.light,
            characterSpacing: 2,
            margin:           [0, 0, 0, 5],
        },
        // Title — .rp-masthead h1
        {
            text:     reportTitle,
            fontSize: 16,
            bold:     true,
            color:    C.ink,
            margin:   [0, 0, 0, 5],
        },
        // Bottom rule (border-bottom: 1px solid in the HTML)
        hRule(C.ink, 0.5, [0, 0, 0, 5]),
    );
    
    
    // ═══════════════════════════════════════════════════════════
    // 1. Overview
    // ═══════════════════════════════════════════════════════════
    
    if (Object.keys(overview).length > 0) {
        doc.content.push(...sectionHead('01 — Overview'));
    
        // Table that mimics the HTML th/td rows:
        // left col = bold key (#3d3d3d), no vertical lines, alternating fill.
        const rows = Object.entries(overview).map(([k, v]) => [
            { text: k, fontSize: 8.5, bold: true, color: C.mid },
            { text: (v && v !== 'None') ? String(v) : '—', fontSize: 8.5, color: C.ink },
        ]);
    
        doc.content.push({
            table:  { widths: ['35%', '*'], body: rows },
            layout: {
                hLineWidth: () => 0.5,
                vLineWidth: () => 0,          // no vertical dividers (like HTML th/td)
                hLineColor: () => C.ruleLight,
                fillColor:  (ri) => ri % 2 === 0 ? C.surface : C.white,
                paddingLeft:   (ci) => ci === 0 ? 9 : 12, // value col has left gap
                paddingRight:  () => 0,
                paddingTop:    () => 10,
                paddingBottom: () => 5,
            },
            margin: [0, 0, 0, 0],
        });
    }


    // ═══════════════════════════════════════════════════════════
    // 2. Observations
    // ═══════════════════════════════════════════════════════════

    if (data.observations && data.observations.length > 0) {
        doc.content.push(...sectionHead('02 — Positive  Observations'));
    
        data.observations.forEach((obs, idx) => {
            const name     = obs.Observation || obs.name     || '';
            const obsText  = obs.Overview    || obs.overview  || '';
            const elements = obs['Affected Elements'] || obs.affected_elements || [];
        
            // # Name — replicates .rp-obs-name::before { content: '✓' }
            doc.content.push({
                text:   `${String(idx + 1)}.  ${name}`,
                fontSize: 9.5,
                bold:   true,
                color:  C.ink,
                margin: [0, 0, 0, 4],
            });
        
            if (obsText) {
                doc.content.push({
                    text:       obsText,
                    fontSize:   8.5,
                    color:      C.mid,
                    lineHeight: 1.6,
                    margin:     [0, 0, 0, 6],
                });
            }
        
            const pills = pillRow(elements);
            if (pills) doc.content.push(pills);
        
            // Border-bottom divider between observations (except last)
            if (idx < data.observations.length - 1) {
                doc.content.push(hRule(C.ruleLight, 0.5, [0, 4, 0, 10]));
            }
        });
    }


    // ═══════════════════════════════════════════════════════════
    // 3. Questionnaire Review
    // ═══════════════════════════════════════════════════════════

    if (data.questionnaire && Object.keys(data.questionnaire).length > 0) {
        doc.content.push(...sectionHead('03 — Security  Questionnaire  Review'));
    
        const headerRow = [
            { text: 'Control Question', fontSize: 8.5, bold: true, color: C.ink },
            { text: 'Status',           fontSize: 8.5, bold: true, color: C.ink, alignment: 'center' },
        ];
        const qRows = [
            headerRow,
            ...Object.entries(data.questionnaire).map(([q, a]) => [
                { text: q, fontSize: 8.5, color: C.mid },
                {
                    text:      a === 'Yes' ? 'Y' : a === 'No' ? 'N' : String(a),
                    fontSize:  8.5,
                    color:     C.ink,
                    alignment: 'center',
                    bold:      a === 'Yes',
                },
            ]),
        ];
            
        doc.content.push({
            table:  { widths: ['*', '12%'], body: qRows },
            layout: {
                hLineWidth: () => 0.5,
                vLineWidth: () => 0.5,
                hLineColor: () => C.rule,
                vLineColor: () => C.rule,
                fillColor:  (ri) => ri === 0 ? C.tableHead : ri % 2 === 0 ? C.surface : C.white,
                paddingLeft:   () => 8,
                paddingRight:  () => 8,
                paddingTop:    () => 6,
                paddingBottom: () => 6,
            },
            margin: [0, 0, 0, 0],
        });
    }


    // ═══════════════════════════════════════════════════════════
    // 4. Risks & Recommendations
    // ═══════════════════════════════════════════════════════════

    doc.content.push(...sectionHead('04 — Risks  &  Recommendations'));

    // Summary paragraph — replicates .rp-summary (border-top style)
    if (data.summary) {
        doc.content.push({
                text:       data.summary,
                fontSize:   8.5,
                color:      C.mid,
                lineHeight: 1.7,
                margin:     [0, 0, 0, 14],
            },
        );
    }

    if (data.vulnerabilities && data.vulnerabilities.length > 0) {
    
        // ── Core technique: one table for ALL cards, 2 rows per card ─────────
        //
        // The table body looks like:
        //   [ [headerRow0], [bodyRow0], [headerRow1], [bodyRow1], ... ]
        //
        // hLineWidth rules:
        //   i === 0                          → top outer border (0.5)
        //   i === table.body.length          → bottom outer border (0.5)
        //   i % 2 === 1 (odd)               → between header and body of SAME card → 0 (hidden)
        //   i % 2 === 0 (even, inner)       → between body of card N and header of card N+1 → 0.5
        //
        // fillColor: even row index → #e8e8e8 (header), odd → white (body)
        // ─────────────────────────────────────────────────────────────────────
    
        const vulnRows = [];
    
        data.vulnerabilities.forEach(risk => {
            const severity = (risk.Severity || risk.severity || 'Info').toUpperCase();
            const riskName = risk.Risk || risk.risk || '';
        
            // ── Header row (even index in vulnRows) ──────────────────────────
            vulnRows.push([{
                columns: [
                    {
                        text:     riskName,
                        bold:     true,
                        fontSize: 9.5,
                        color:    C.ink,
                        width:    '*',
                    },
                    {
                        text:             severity,
                        fontSize:         7,
                        color:            C.light,
                        bold:             true,
                        characterSpacing: 1,
                        width:            'auto',
                        alignment:        'right',
                    },
                ],
            }]);
        
            // ── Body row (odd index in vulnRows) ─────────────────────────────
            // margin: [8, 0, 0, 0] adds the body's extra left indent
            // (replicates padding: 1.25rem 2.5rem 1.5rem on .rp-vuln-body)
            const bodyStack = buildVulnBody(risk);
            vulnRows.push([{
                stack:  bodyStack.length ? bodyStack : [{ text: '' }],
                margin: [8, 0, 0, 0],
            }]);
        });
    
        doc.content.push({
            table:  { widths: ['*'], body: vulnRows },
            layout: {
                hLineWidth: (i, node) => {
                    if (i === 0 || i === node.table.body.length) return 0.5; // outer edges
                    if (i % 2 === 1) return 0;                               // header → body (hidden)
                    return 0.5;                                               // card → card
                },
                vLineWidth: () => 0.5,
                hLineColor: () => C.rule,
                vLineColor: () => C.rule,
                // Even rows = card headers (#e8e8e8), odd rows = card bodies (white)
                fillColor:     (ri) => ri % 2 === 0 ? C.ruleLight : C.white,
                paddingLeft:   () => 12,
                paddingRight:  () => 12,
                // Different top/bottom padding for header vs body rows
                paddingTop:    (ri) => ri % 2 === 0 ? 9  : 14,
                paddingBottom: (ri) => ri % 2 === 0 ? 9  : 14,
            },
            margin: [0, 0, 0, 15],
        });
    
    } else {
        doc.content.push({
            text:    'No vulnerabilities were identified in this report.',
            fontSize: 8.5,
            color:   C.light,
            italics: true,
            margin:  [0, 0, 0, 15],
        });
    }


    // ═══════════════════════════════════════════════════════════════════════════
    // 5. Technical Scan Results
    // ═══════════════════════════════════════════════════════════════════════════
 
    doc.content.push(...sectionHead('05 — Technical  Scan  Results'));
 
    if (data.scan_metadata && Object.keys(data.scan_metadata).length > 0) {
        const metaRows = Object.entries(data.scan_metadata).map(([k, v]) => [
            { text: k,              fontSize: 8.5, bold: true, color: C.mid },
            { text: String(v != null ? v : '—'), fontSize: 8.5, color: C.ink },
        ]);
 
        doc.content.push({
            table:  { widths: ['35%', '*'], body: metaRows },
            layout: {
                hLineWidth: () => 0.5,
                vLineWidth: () => 0,
                hLineColor: () => C.ruleLight,
                fillColor:  (ri) => ri % 2 === 0 ? C.surface : C.white,
                paddingLeft:   (ci) => ci === 0 ? 9 : 12,
                paddingRight:  () => 0,
                paddingTop:    () => 8,
                paddingBottom: () => 4,
            },
            margin: [0, 0, 0, 14],
        });
    }
 
    const portFindings = data.port_findings || [];
 
    if (portFindings.length > 0) {
        doc.content.push({
            text:             'Open  Ports  &  Services',
            fontSize:         6.5,
            bold:             true,
            color:            C.ink,
            characterSpacing: 1.5,
            margin:           [0, 0, 0, 6],
        });
 
        const sevAbbr = {
            CRITICAL: 'CRIT', Critical: 'CRIT',
            HIGH:     'HIGH', High:     'HIGH',
            MEDIUM:   'MED',  Medium:   'MED',
            LOW:      'LOW',  Low:      'LOW',
            INFO:     'INFO', Info:     'INFO',
        };
 
        const headerRow = [
            { text: 'Port',     fontSize: 7.5, bold: true, color: C.ink },
            { text: 'Proto',    fontSize: 7.5, bold: true, color: C.ink },
            { text: 'Service',  fontSize: 7.5, bold: true, color: C.ink },
            { text: 'Severity', fontSize: 7.5, bold: true, color: C.ink, alignment: 'center' },
            { text: 'Detail',   fontSize: 7.5, bold: true, color: C.ink },
        ];
 
        const dataRows = portFindings.map(f => {
            const detail = (f.information || f.description || '').slice(0, 120);
            const abbr   = sevAbbr[f.severity] || 'INFO';
            return [
                { text: String(f.portid   || ''), fontSize: 7.5, color: C.ink },
                { text: String(f.protocol || '').toUpperCase(), fontSize: 7.5, color: C.mid },
                { text: String(f.service  || ''), fontSize: 7.5, color: C.mid },
                { text: abbr, fontSize: 7, color: C.mid, alignment: 'center', bold: true },
                { text: detail, fontSize: 7.5, color: C.mid },
            ];
        });
 
        doc.content.push({
            table: {
                widths: ['8%', '8%', '12%', '9%', '*'],
                body:   [headerRow, ...dataRows],
            },
            layout: {
                hLineWidth: () => 0.5,
                vLineWidth: () => 0.5,
                hLineColor: () => C.rule,
                vLineColor: () => C.rule,
                fillColor:  (ri) => ri === 0 ? C.tableHead : ri % 2 === 0 ? C.surface : C.white,
                paddingLeft:   () => 5,
                paddingRight:  () => 5,
                paddingTop:    () => 4,
                paddingBottom: () => 4,
            },
            margin: [0, 0, 0, 15],
        });
 
    } else {
        doc.content.push({
            text:    'Detailed port findings are not available for this report.',
            fontSize: 8.5,
            color:   C.light,
            italics: true,
            margin:  [0, 0, 0, 15],
        });
    }


    // ═══════════════════════════════════════════════════════════
    // 6. Conclusion — replicates .rp-conclusion (border-top style)
    // ═══════════════════════════════════════════════════════════

    if (data.conclusion) {
        doc.content.push(...sectionHead('06 — Conclusion'));
        doc.content.push({
                text:       data.conclusion,
                fontSize:   8.5,
                color:      C.mid,
                lineHeight: 1.7,
            },
        );
    }


    // ═══════════════════════════════════════════════════════════
    // Footer — replicates .rp-footer-text
    // ═══════════════════════════════════════════════════════════

    doc.footer = (currentPage, pageCount) => ({
        columns: [
            {
                text:      'Vuleevu Inc — RePortly',
                fontSize:  7,
                color:     C.light,
                alignment: 'left',
            },
            {
                text:      `Page ${currentPage} / ${pageCount}`,
                fontSize:  7,
                color:     C.light,
                alignment: 'right',
            },
        ],
        margin: [40, 10, 40, 0],
    });

    return doc;
}