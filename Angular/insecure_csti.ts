import { Component, OnInit } from '@angular/core';

@Component({
  selector: 'app-vulnerable-csti',
  template: `
    <div class="container">
      <h2>Vulnerable CSTI Component</h2>
      
      <!-- VULNERABILITY 1: Direct template string interpolation without sanitization -->
      <div [innerHTML]="userInput"></div>
      
      <!-- VULNERABILITY 2: Unsafe template binding -->
      <div>{{ userInput }}</div>
      
      <!-- VULNERABILITY 3: Direct template expression evaluation -->
      <div [ngTemplateOutlet]="dynamicTemplate"></div>
      
      <!-- VULNERABILITY 4: Unsafe dynamic component creation -->
      <div #dynamicComponent></div>
      
      <!-- VULNERABILITY 5: Unsafe property binding -->
      <div [style]="userInput"></div>
      
      <!-- VULNERABILITY 6: Unsafe event binding -->
      <button (click)="executeUserInput()">Execute</button>
      
      <!-- VULNERABILITY 7: Unsafe attribute binding -->
      <div [attr.data-content]="userInput"></div>
      
      <!-- VULNERABILITY 8: Unsafe class binding -->
      <div [class]="userInput"></div>
      
      <!-- VULNERABILITY 9: Unsafe style binding -->
      <div [style.background]="userInput"></div>
      
      <!-- VULNERABILITY 10: Unsafe ngModel binding -->
      <input [(ngModel)]="userInput" placeholder="Enter template">
      
      <!-- VULNERABILITY 11: Unsafe template reference variable -->
      <div #templateRef [innerHTML]="templateRef.innerHTML"></div>
      
      <!-- VULNERABILITY 12: Unsafe dynamic template creation -->
      <div [innerHTML]="createTemplate()"></div>
      
      <!-- VULNERABILITY 13: Unsafe component property access -->
      <div>{{ componentProperty }}</div>
      
      <!-- VULNERABILITY 14: Unsafe method call in template -->
      <div>{{ executeMethod(userInput) }}</div>
      
      <!-- VULNERABILITY 15: Unsafe pipe usage -->
      <div>{{ userInput | unsafePipe }}</div>
    </div>
  `,
  styles: [`
    .container { padding: 20px; }
  `]
})
export class VulnerableCstiComponent implements OnInit {
  // VULNERABILITY 16: Unsafe property initialization
  userInput: string = '';
  componentProperty: any = {};
  
  constructor() {
    // VULNERABILITY 17: Unsafe constructor initialization
    this.initializeComponent();
  }
  
  ngOnInit() {
    // VULNERABILITY 18: Unsafe initialization in lifecycle hook
    this.loadUserData();
  }
  
  // VULNERABILITY 19: Unsafe method implementation
  executeUserInput() {
    eval(this.userInput);
  }
  
  // VULNERABILITY 20: Unsafe template creation
  createTemplate() {
    return this.userInput;
  }
  
  // VULNERABILITY 21: Unsafe method execution
  executeMethod(input: string) {
    return eval(input);
  }
  
  // VULNERABILITY 22: Unsafe initialization
  private initializeComponent() {
    this.userInput = localStorage.getItem('userInput') || '';
  }
  
  // VULNERABILITY 23: Unsafe data loading
  private loadUserData() {
    // Simulating unsafe data loading
    this.componentProperty = {
      template: this.userInput,
      execute: (code: string) => eval(code)
    };
  }
}

// VULNERABILITY 24: Unsafe pipe implementation
import { Pipe, PipeTransform } from '@angular/core';

@Pipe({
  name: 'unsafePipe'
})
export class UnsafePipe implements PipeTransform {
  transform(value: string): string {
    // VULNERABILITY 25: Unsafe pipe transformation
    return eval(value) || value;
  }
}

// VULNERABILITY 26: Unsafe service implementation
import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class UnsafeTemplateService {
  // VULNERABILITY 27: Unsafe service method
  executeTemplate(template: string) {
    return eval(template);
  }
  
  // VULNERABILITY 28: Unsafe data storage
  saveTemplate(template: string) {
    localStorage.setItem('userTemplate', template);
  }
  
  // VULNERABILITY 29: Unsafe data retrieval
  getTemplate() {
    return localStorage.getItem('userTemplate') || '';
  }
}

// VULNERABILITY 30: Unsafe module configuration
import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { FormsModule } from '@angular/forms';

@NgModule({
  declarations: [
    VulnerableCstiComponent,
    UnsafePipe
  ],
  imports: [
    BrowserModule,
    FormsModule
  ],
  providers: [
    UnsafeTemplateService
  ],
  bootstrap: [VulnerableCstiComponent]
})
export class VulnerableAppModule { }

// Example of how to exploit these vulnerabilities:
/*
1. Template Injection:
{{constructor.constructor('alert(1)')()}}

2. Property Access:
{{componentProperty.execute('alert(1)')}}

3. Method Execution:
{{executeMethod('alert(1)')}}

4. Pipe Exploitation:
{{'alert(1)' | unsafePipe}}

5. Service Exploitation:
{{unsafeTemplateService.executeTemplate('alert(1)')}}

6. Dynamic Template:
<script>alert(1)</script>

7. Event Handler:
(click)="executeUserInput()" with payload: alert(1)

8. Style Injection:
[style]="'background: url(javascript:alert(1))'"

9. Attribute Injection:
[attr.data-content]="'javascript:alert(1)'"

10. Class Injection:
[class]="'javascript:alert(1)'"
*/
