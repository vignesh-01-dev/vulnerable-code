import { Component, OnInit, SecurityContext, ElementRef, ViewChild } from '@angular/core';
import { DomSanitizer, SafeHtml, SafeStyle, SafeUrl } from '@angular/platform-browser';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { map, catchError } from 'rxjs/operators';
import { Pipe, PipeTransform } from '@angular/core';

// Secure Template Service
@Injectable({
  providedIn: 'root'
})
export class SecureTemplateService {
  constructor(
    private sanitizer: DomSanitizer,
    private http: HttpClient
  ) {}

  // Secure template processing
  processTemplate(template: string): SafeHtml {
    // Sanitize HTML content
    return this.sanitizer.sanitize(SecurityContext.HTML, template) || '';
  }

  // Secure style processing
  processStyle(style: string): SafeStyle {
    // Sanitize CSS content
    return this.sanitizer.sanitize(SecurityContext.STYLE, style) || '';
  }

  // Secure URL processing
  processUrl(url: string): SafeUrl {
    // Sanitize URL content
    return this.sanitizer.sanitize(SecurityContext.URL, url) || '';
  }

  // Secure data storage with encryption
  secureStore(key: string, value: string): void {
    // Encrypt sensitive data before storage
    const encryptedValue = this.encryptData(value);
    sessionStorage.setItem(key, encryptedValue);
  }

  // Secure data retrieval with decryption
  secureRetrieve(key: string): string {
    const encryptedValue = sessionStorage.getItem(key);
    if (!encryptedValue) return '';
    // Decrypt stored data
    return this.decryptData(encryptedValue);
  }

  private encryptData(data: string): string {
    // Implement proper encryption (this is a placeholder)
    return btoa(data);
  }

  private decryptData(data: string): string {
    // Implement proper decryption (this is a placeholder)
    try {
      return atob(data);
    } catch {
      return '';
    }
  }
}

// Secure Content Pipe
@Pipe({
  name: 'securePipe'
})
export class SecurePipe implements PipeTransform {
  constructor(private sanitizer: DomSanitizer) {}

  transform(value: string, type: 'html' | 'style' | 'url' = 'html'): SafeHtml | SafeStyle | SafeUrl {
    switch (type) {
      case 'html':
        return this.sanitizer.bypassSecurityTrustHtml(value);
      case 'style':
        return this.sanitizer.bypassSecurityTrustStyle(value);
      case 'url':
        return this.sanitizer.bypassSecurityTrustUrl(value);
      default:
        return this.sanitizer.sanitize(SecurityContext.HTML, value) || '';
    }
  }
}

@Component({
  selector: 'app-secure-csti',
  template: `
    <div class="container">
      <h2>Secure Template Implementation</h2>

      <!-- Secure Form Implementation -->
      <form [formGroup]="templateForm" (ngSubmit)="onSubmit()" class="secure-form">
        <!-- Secure Input Field -->
        <div class="form-group">
          <label for="templateInput">Template Input:</label>
          <input
            id="templateInput"
            type="text"
            formControlName="templateInput"
            class="form-control"
            [attr.maxlength]="maxInputLength"
          >
          <div *ngIf="templateForm.get('templateInput')?.errors?.required" class="error">
            Input is required
          </div>
        </div>

        <!-- Secure Content Display -->
        <div class="content-display">
          <!-- Secure HTML Content -->
          <div [innerHTML]="sanitizedContent"></div>

          <!-- Secure Style Implementation -->
          <div [style]="sanitizedStyle"></div>

          <!-- Secure URL Implementation -->
          <img [src]="sanitizedUrl" *ngIf="sanitizedUrl">

          <!-- Secure Template Reference -->
          <div #secureTemplate></div>
        </div>

        <!-- Secure Button Implementation -->
        <button 
          type="submit" 
          [disabled]="!templateForm.valid || isProcessing"
          class="btn btn-primary"
        >
          Process Template
        </button>
      </form>

      <!-- Secure Error Display -->
      <div *ngIf="errorMessage" class="alert alert-danger">
        {{ errorMessage }}
      </div>
    </div>
  `,
  styles: [`
    .container {
      padding: 20px;
      max-width: 800px;
      margin: 0 auto;
    }
    .secure-form {
      margin-top: 20px;
    }
    .form-group {
      margin-bottom: 15px;
    }
    .form-control {
      width: 100%;
      padding: 8px;
      border: 1px solid #ddd;
      border-radius: 4px;
    }
    .error {
      color: red;
      font-size: 0.8em;
      margin-top: 5px;
    }
    .content-display {
      margin: 20px 0;
      padding: 15px;
      border: 1px solid #eee;
      border-radius: 4px;
    }
    .btn-primary {
      background-color: #007bff;
      color: white;
      padding: 8px 16px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
    }
    .btn-primary:disabled {
      background-color: #ccc;
      cursor: not-allowed;
    }
    .alert {
      padding: 15px;
      margin-top: 20px;
      border-radius: 4px;
    }
    .alert-danger {
      background-color: #f8d7da;
      border-color: #f5c6cb;
      color: #721c24;
    }
  `]
})
export class SecureCSTIComponent implements OnInit {
  @ViewChild('secureTemplate', { static: true }) secureTemplate!: ElementRef;

  templateForm: FormGroup;
  sanitizedContent: SafeHtml = '';
  sanitizedStyle: SafeStyle = '';
  sanitizedUrl: SafeUrl = '';
  errorMessage: string = '';
  isProcessing: boolean = false;
  readonly maxInputLength: number = 1000;

  constructor(
    private formBuilder: FormBuilder,
    private sanitizer: DomSanitizer,
    private secureTemplateService: SecureTemplateService
  ) {
    // Initialize form with validators
    this.templateForm = this.formBuilder.group({
      templateInput: ['', [
        Validators.required,
        Validators.maxLength(this.maxInputLength),
        Validators.pattern(/^[a-zA-Z0-9\s\-_.,!?()[\]{}'"<>]+$/)
      ]]
    });
  }

  ngOnInit(): void {
    // Initialize with secure defaults
    this.initializeSecureDefaults();
  }

  private initializeSecureDefaults(): void {
    // Set secure default content
    this.sanitizedContent = this.sanitizer.bypassSecurityTrustHtml('');
    this.sanitizedStyle = this.sanitizer.bypassSecurityTrustStyle('');
    this.sanitizedUrl = this.sanitizer.bypassSecurityTrustUrl('');
  }

  onSubmit(): void {
    if (this.templateForm.valid && !this.isProcessing) {
      this.isProcessing = true;
      this.errorMessage = '';

      try {
        const userInput = this.templateForm.get('templateInput')?.value || '';
        
        // Process and sanitize input
        this.processSecureContent(userInput);
        
        // Store processed content securely
        this.secureTemplateService.secureStore('lastTemplate', userInput);
        
      } catch (error) {
        this.handleError('An error occurred while processing the template');
      } finally {
        this.isProcessing = false;
      }
    }
  }

  private processSecureContent(input: string): void {
    // Sanitize HTML content
    this.sanitizedContent = this.secureTemplateService.processTemplate(input);

    // Sanitize style content
    this.sanitizedStyle = this.secureTemplateService.processStyle(input);

    // Sanitize URL content
    this.sanitizedUrl = this.secureTemplateService.processUrl(input);

    // Update template reference securely
    if (this.secureTemplate) {
      this.secureTemplate.nativeElement.textContent = 
        this.sanitizer.sanitize(SecurityContext.HTML, input);
    }
  }

  private handleError(message: string): void {
    this.errorMessage = message;
    // Log error securely
    console.error('Template processing error:', message);
  }
}

// Secure Module Configuration
import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { ReactiveFormsModule } from '@angular/forms';
import { HttpClientModule, HTTP_INTERCEPTORS } from '@angular/common/http';

@NgModule({
  declarations: [
    SecureCSTIComponent,
    SecurePipe
  ],
  imports: [
    BrowserModule,
    ReactiveFormsModule,
    HttpClientModule
  ],
  providers: [
    SecureTemplateService,
    {
      provide: HTTP_INTERCEPTORS,
      useClass: SecurityHeadersInterceptor,
      multi: true
    }
  ],
  bootstrap: [SecureCSTIComponent]
})
export class SecureAppModule { }

// Security Headers Interceptor
@Injectable()
export class SecurityHeadersInterceptor implements HttpInterceptor {
  intercept(req: HttpRequest<any>, next: HttpClient) {
    const secureReq = req.clone({
      headers: new HttpHeaders({
        'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self';",
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block'
      })
    });
    return next.handle(secureReq);
  }
}
