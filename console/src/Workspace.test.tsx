import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it } from 'vitest';
import { Context, PageBar } from './ui';
import type { Session } from './api';

const session:Session={user:{id:'synthetic-user',email:'operator@example.invalid',display_name:'Operator'},organization:{id:'synthetic-org',name:'Synthetic organization',role:'owner'},organizations:[],permissions:[],csrf_token:'synthetic-csrf',edition:'community'};
afterEach(cleanup);

it('keeps page actions available while explanatory content is disclosed on demand',()=>{
  render(<Context.Provider value={{session,language:'fr',refreshSession:async()=>undefined}}>
    <PageBar title="Inventaire" actions={<button type="button">Actualiser</button>} info={<p>Contexte de la vue <a href="#privacy">Confidentialité</a></p>}/>
  </Context.Provider>);
  expect(screen.getByRole('heading',{level:1,name:'Inventaire'})).toBeVisible();
  expect(screen.getByRole('button',{name:'Actualiser'})).toBeVisible();
  const summary=screen.getByText('À propos de cette vue');
  const details=summary.closest('details')!;
  expect(details.open).toBe(false);
  expect(screen.getByText('Confidentialité')).not.toBeVisible();
  fireEvent.click(summary);
  expect(details.open).toBe(true);
  expect(screen.getByRole('link',{name:'Confidentialité'})).toHaveAttribute('href','#privacy');
  fireEvent.click(summary);
  expect(details.open).toBe(false);
  expect(screen.getByRole('button',{name:'Actualiser'})).toBeEnabled();
});

it('renders untrusted explanatory text without interpreting markup or inserting a useless help control',()=>{
  const view=render(<Context.Provider value={{session,language:'en',refreshSession:async()=>undefined}}>
    <PageBar title="Inventory" info={'<img src=x onerror=alert(1)>'}/>
  </Context.Provider>);
  fireEvent.click(screen.getByText('About this view'));
  expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeVisible();
  expect(document.querySelector('img')).toBeNull();
  view.rerender(<Context.Provider value={{session,language:'en',refreshSession:async()=>undefined}}><PageBar title="Inventory"/></Context.Provider>);
  expect(document.querySelector('details')).toBeNull();
});
