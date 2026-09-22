"""Local-only PDF generation. Untrusted strings are XML-escaped, never markup."""
from pathlib import Path
from xml.sax.saxutils import escape
import io,os,tempfile

def pdf_reports(directory,run):
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet,ParagraphStyle
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle,PageBreak,KeepTogether
    import reportlab
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    fonts=Path(reportlab.__file__).parent/'fonts'
    pdfmetrics.registerFont(TTFont('Vera',str(fonts/'Vera.ttf')))
    pdfmetrics.registerFont(TTFont('Vera-Bold',str(fonts/'VeraBd.ttf')))
    styles=getSampleStyleSheet()
    for style in styles.byName.values(): style.fontName='Vera'
    styles['Title'].fontName='Vera-Bold';styles['Heading2'].fontName='Vera-Bold'
    styles.add(ParagraphStyle('Brand',fontName='Vera-Bold',fontSize=11,textColor=colors.HexColor('#178a71'),spaceAfter=16))
    styles['Title'].fontSize=28;styles['Title'].leading=33;styles['Title'].alignment=TA_LEFT
    styles['BodyText'].fontSize=9;styles['BodyText'].leading=13;styles['BodyText'].spaceAfter=8
    styles['Heading2'].fontSize=15;styles['Heading2'].spaceBefore=14
    def para(text,style='BodyText'): return Paragraph(escape(str(text)).replace('\n','<br/>'),styles[style])
    def footer(canvas,doc):
        canvas.saveState();canvas.setStrokeColor(colors.HexColor('#d9e1ea'));canvas.line(40,38,555,38)
        canvas.setFont('Vera',8);canvas.setFillColor(colors.HexColor('#637386'));canvas.drawString(40,26,'SECAUDIT / Authorized assessment / '+run['id'][:12]);canvas.drawRightString(555,26,str(doc.page));canvas.restoreState()
    for kind in ('executive','technical'):
        items=[para('SECAUDIT  /  SECURITY ASSESSMENT','Brand'),para(kind.capitalize()+' report','Title'),para('Evidence-led findings. Transparent coverage.'),Spacer(1,16)]
        summary=[['RUN',run['id'][:16]],['NETWORK MODE',run['mode']],['STATE',run['status']],['CANDIDATE FINDINGS',str(len(run['findings']))],['GENERATED',run.get('finished',run.get('started',''))]]
        table=Table([[para(a),para(b)] for a,b in summary],colWidths=[140,375]);table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),colors.HexColor('#f1f5f9')),('BOX',(0,0),(-1,-1),.5,colors.HexColor('#d9e1ea')),('VALIGN',(0,0),(-1,-1),'TOP'),('TOPPADDING',(0,0),(-1,-1),9),('BOTTOMPADDING',(0,0),(-1,-1),5)]));items+=[table,Spacer(1,16),para('Assessment boundaries','Heading2')]
        items += [para(x) for x in run.get('limitations',[])]
        ai=run.get('ai_usage',{})
        items += [para('AI usage','Heading2'),para('Enabled: '+str(ai.get('enabled',False))+'; provider: '+str(ai.get('provider','none'))+'; verification: '+str(ai.get('verified','not used')))]
        items += [para('Coverage','Heading2')]
        for c in run['coverage']: items+=[KeepTogether([para(c['module']+' - '+c['status'])]+([para(c['reason'])] if kind=='technical' else []))]
        if run.get('events'): items+=[para('Execution notes','Heading2'),*[para(x) for x in run['events']]]
        if kind=='technical':
            items+=[Spacer(1,18),para('Technical findings','Title')]
            for i,f in enumerate(run['findings'],1):
                group_start=len(items)
                items+=[para(str(i)+'. '+f['title'],'Heading2'),para(f['severity']+' / '+f['confidence']+' / '+f['validation_status']),para('Asset: '+f['asset']+(':'+str(f['line']) if f['line'] else '')),para(f['description']),para('Evidence: '+'; '.join(f['evidence'])),para('Remediation: '+f['remediation']),para('Retest: '+f['retest'])]
                for m in f.get('mappings',[]): items.append(para('Related evidence: '+m['framework']+' '+m['version']+' / '+m['control']))
                items[group_start:]=[KeepTogether(items[group_start:])]
        else:
            items+=[para('Priority actions','Heading2')]
            ranked=sorted(run['findings'],key=lambda f:('CRITICAL','HIGH','MEDIUM','LOW','INFO').index(f['severity']))
            items += [para(f['title']+': '+f['remediation']) for f in ranked[:8]]
        buffer=io.BytesIO();SimpleDocTemplate(buffer,pagesize=A4,rightMargin=40,leftMargin=40,topMargin=45,bottomMargin=54,title='Secaudit '+kind+' assessment',author='Secaudit').build(items,onFirstPage=footer,onLaterPages=footer)
        path=Path(directory)/(kind+'.pdf');fd,temp=tempfile.mkstemp(dir=path.parent)
        try:
            with os.fdopen(fd,'wb') as f: f.write(buffer.getvalue());f.flush();os.fsync(f.fileno())
            os.replace(temp,path)
        finally:
            if os.path.exists(temp): os.unlink(temp)
